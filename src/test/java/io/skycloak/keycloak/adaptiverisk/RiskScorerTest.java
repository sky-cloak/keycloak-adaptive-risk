package io.skycloak.keycloak.adaptiverisk;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RiskScorerTest {

    private static final long NOW = 1_780_000_000_000L; // a fixed instant, 14:26 UTC
    private static final int HOUR = 14;
    private static final long MINUTE = 60_000L;

    private final RiskSettings defaults = RiskSettings.defaults();

    /** A profile past learning that has seen the device, network, country and hour of {@link #familiar()}. */
    private static RiskProfile establishedProfile() {
        RiskProfile profile = new RiskProfile();
        for (int i = 3; i >= 1; i--) {
            profile.recordSuccess(familiar().at(NOW - Duration.ofDays(i).toMillis()), Duration.ofDays(90));
        }
        return profile;
    }

    private static LoginSignals familiar() {
        return new LoginSignals("device-hash-a", "203.0.113.0/24", "CA", HOUR, NOW, null);
    }

    @Test
    void familiarLoginScoresZeroAndLow() {
        Assessment a = RiskScorer.score(defaults, establishedProfile(), familiar());

        assertEquals(0, a.score());
        assertEquals(RiskLevel.LOW, a.level());
        assertEquals(List.of(), a.reasons());
    }

    @Test
    void newDeviceWeighs30AndReachesMedium() {
        Assessment a = RiskScorer.score(defaults, establishedProfile(), familiar().withDevice("device-hash-b"));

        assertEquals(30, a.score());
        assertEquals(RiskLevel.MEDIUM, a.level());
        assertEquals(List.of(Reason.NEW_DEVICE), a.reasons());
    }

    @Test
    void missingDeviceCookieCountsAsNewDevice() {
        Assessment a = RiskScorer.score(defaults, establishedProfile(), familiar().withDevice(null));

        assertEquals(List.of(Reason.NEW_DEVICE), a.reasons());
    }

    @Test
    void newNetworkWeighs15() {
        Assessment a = RiskScorer.score(defaults, establishedProfile(), familiar().withNetwork("198.51.100.0/24"));

        assertEquals(15, a.score());
        assertEquals(RiskLevel.LOW, a.level());
        assertEquals(List.of(Reason.NEW_NETWORK), a.reasons());
    }

    @Test
    void unknownNetworkIsNotAReason() {
        Assessment a = RiskScorer.score(defaults, establishedProfile(), familiar().withNetwork(null));

        assertEquals(List.of(), a.reasons());
    }

    @Test
    void newCountryWeighs30() {
        // Last login was three days ago, so the country change is not rapid.
        Assessment a = RiskScorer.score(defaults, establishedProfile(), familiar().withCountry("FR"));

        assertEquals(30, a.score());
        assertEquals(List.of(Reason.NEW_COUNTRY), a.reasons());
    }

    @Test
    void countryReasonsAreSkippedWhenCountryUnknown() {
        RiskProfile profile = establishedProfile();
        profile.recordSuccess(familiar().at(NOW - 10 * MINUTE), Duration.ofDays(90));

        Assessment a = RiskScorer.score(defaults, profile, familiar().withCountry(null));

        assertEquals(List.of(), a.reasons());
    }

    @Test
    void newCountryNeedsCountryHistory() {
        // A profile learned before the country header was configured has no countries yet:
        // the first country it sees is a baseline, not an anomaly.
        RiskProfile profile = new RiskProfile();
        for (int i = 3; i >= 1; i--) {
            profile.recordSuccess(familiar().withCountry(null).at(NOW - Duration.ofDays(i).toMillis()), Duration.ofDays(90));
        }

        Assessment a = RiskScorer.score(defaults, profile, familiar());

        assertEquals(List.of(), a.reasons());
    }

    @Test
    void rapidCountryChangeWithinTwoHoursAddsToNewCountry() {
        RiskProfile profile = establishedProfile();
        profile.recordSuccess(familiar().at(NOW - 119 * MINUTE), Duration.ofDays(90));

        Assessment a = RiskScorer.score(defaults, profile, familiar().withCountry("FR"));

        assertEquals(70, a.score());
        assertEquals(RiskLevel.HIGH, a.level());
        assertEquals(List.of(Reason.NEW_COUNTRY, Reason.RAPID_COUNTRY_CHANGE), a.reasons());
    }

    @Test
    void rapidCountryChangeAlsoFiresForAKnownCountry() {
        RiskProfile profile = establishedProfile();
        profile.recordSuccess(familiar().withCountry("FR").at(NOW - Duration.ofDays(1).toMillis() + MINUTE), Duration.ofDays(90));
        profile.recordSuccess(familiar().at(NOW - 30 * MINUTE), Duration.ofDays(90));

        Assessment a = RiskScorer.score(defaults, profile, familiar().withCountry("FR"));

        assertEquals(40, a.score());
        assertEquals(List.of(Reason.RAPID_COUNTRY_CHANGE), a.reasons());
    }

    @Test
    void countryChangeAfterTheWindowIsNotRapid() {
        RiskProfile profile = establishedProfile();
        profile.recordSuccess(familiar().at(NOW - 121 * MINUTE), Duration.ofDays(90));

        Assessment a = RiskScorer.score(defaults, profile, familiar().withCountry("FR"));

        assertEquals(List.of(Reason.NEW_COUNTRY), a.reasons());
    }

    @Test
    void recentFailuresWeigh25FromThreeFailuresInTheLastHour() {
        Assessment three = RiskScorer.score(defaults, establishedProfile(),
                familiar().withFailures(new Failures(3, NOW - 59 * MINUTE)));
        Assessment two = RiskScorer.score(defaults, establishedProfile(),
                familiar().withFailures(new Failures(2, NOW - MINUTE)));
        Assessment stale = RiskScorer.score(defaults, establishedProfile(),
                familiar().withFailures(new Failures(5, NOW - 61 * MINUTE)));

        assertEquals(25, three.score());
        assertEquals(List.of(Reason.RECENT_FAILURES), three.reasons());
        assertEquals(List.of(), two.reasons());
        assertEquals(List.of(), stale.reasons());
    }

    @Test
    void recentFailuresSkippedWithoutBruteForceRecords() {
        // null failures means brute force detection is off.
        Assessment a = RiskScorer.score(defaults, establishedProfile(), familiar().withFailures(null));

        assertEquals(List.of(), a.reasons());
    }

    @Test
    void unusualHourWeighs10AndAdjacentHoursCountAsUsual() {
        Assessment adjacent = RiskScorer.score(defaults, establishedProfile(), familiar().withHour(HOUR + 1));
        Assessment unusual = RiskScorer.score(defaults, establishedProfile(), familiar().withHour(HOUR + 2));

        assertEquals(List.of(), adjacent.reasons());
        assertEquals(10, unusual.score());
        assertEquals(List.of(Reason.UNUSUAL_HOUR), unusual.reasons());
    }

    @Test
    void unusualHourWrapsAroundMidnight() {
        RiskProfile profile = new RiskProfile();
        for (int i = 3; i >= 1; i--) {
            profile.recordSuccess(familiar().withHour(23).at(NOW - Duration.ofDays(i).toMillis()), Duration.ofDays(90));
        }

        assertEquals(List.of(), RiskScorer.score(defaults, profile, familiar().withHour(0)).reasons());
        assertEquals(List.of(Reason.UNUSUAL_HOUR), RiskScorer.score(defaults, profile, familiar().withHour(1)).reasons());
    }

    @Test
    void scoreIsTheCappedSumOfWeights() {
        RiskProfile profile = establishedProfile();
        profile.recordSuccess(familiar().at(NOW - 10 * MINUTE), Duration.ofDays(90));
        LoginSignals everything = new LoginSignals(null, "198.51.100.0/24", "FR", HOUR + 6, NOW,
                new Failures(4, NOW - MINUTE));

        Assessment a = RiskScorer.score(defaults, profile, everything);

        // 30 + 15 + 30 + 40 + 25 + 10 = 150, capped.
        assertEquals(100, a.score());
        assertEquals(RiskLevel.HIGH, a.level());
        assertEquals(List.of(Reason.NEW_DEVICE, Reason.NEW_NETWORK, Reason.NEW_COUNTRY,
                Reason.RAPID_COUNTRY_CHANGE, Reason.RECENT_FAILURES, Reason.UNUSUAL_HOUR), a.reasons());
    }

    @Test
    void levelThresholdsAreInclusive() {
        RiskSettings settings = RiskSettings.fromConfig(Map.of(
                RiskSettings.MEDIUM_THRESHOLD, "15",
                RiskSettings.HIGH_THRESHOLD, "45"));

        LoginSignals newNetwork = familiar().withNetwork("198.51.100.0/24");
        LoginSignals newNetworkAndDevice = newNetwork.withDevice("device-hash-b");

        assertEquals(RiskLevel.LOW, RiskScorer.score(settings, establishedProfile(), familiar()).level());
        assertEquals(RiskLevel.MEDIUM, RiskScorer.score(settings, establishedProfile(), newNetwork).level());
        assertEquals(RiskLevel.HIGH, RiskScorer.score(settings, establishedProfile(), newNetworkAndDevice).level());
    }

    @Test
    void configuredWeightsReplaceDefaults() {
        RiskSettings settings = RiskSettings.fromConfig(Map.of(RiskSettings.weightKey(Reason.NEW_DEVICE), "65"));

        Assessment a = RiskScorer.score(settings, establishedProfile(), familiar().withDevice(null));

        assertEquals(65, a.score());
        assertEquals(RiskLevel.HIGH, a.level());
    }

    @Test
    void aZeroWeightTurnsTheReasonOffEntirely() {
        RiskSettings settings = RiskSettings.fromConfig(Map.of(RiskSettings.weightKey(Reason.NEW_DEVICE), "0"));

        Assessment a = RiskScorer.score(settings, establishedProfile(),
                familiar().withDevice("device-hash-b").withNetwork("198.51.100.0/24"));

        assertEquals(15, a.score());
        assertEquals(List.of(Reason.NEW_NETWORK), a.reasons());
    }

    @Test
    void learningProfileScoresTheLearningScoreWithoutHistoryReasons() {
        RiskProfile twoLogins = new RiskProfile();
        twoLogins.recordSuccess(familiar().at(NOW - Duration.ofDays(2).toMillis()), Duration.ofDays(90));
        twoLogins.recordSuccess(familiar().at(NOW - Duration.ofDays(1).toMillis()), Duration.ofDays(90));
        LoginSignals stranger = new LoginSignals(null, "198.51.100.0/24", "FR", HOUR + 6, NOW, null);

        Assessment a = RiskScorer.score(defaults, twoLogins, stranger);

        assertEquals(0, a.score());
        assertEquals(RiskLevel.LOW, a.level());
        assertEquals(List.of(Reason.LEARNING), a.reasons());
    }

    @Test
    void learningStillCountsRecentFailuresOnTopOfTheLearningScore() {
        RiskSettings settings = RiskSettings.fromConfig(Map.of(RiskSettings.LEARNING_SCORE, "20"));

        Assessment a = RiskScorer.score(settings, new RiskProfile(),
                familiar().withFailures(new Failures(3, NOW - MINUTE)));

        assertEquals(45, a.score());
        assertEquals(RiskLevel.MEDIUM, a.level());
        assertEquals(List.of(Reason.LEARNING, Reason.RECENT_FAILURES), a.reasons());
    }

    @Test
    void learningLoginsAreConfigurable() {
        RiskSettings settings = RiskSettings.fromConfig(Map.of(RiskSettings.LEARNING_LOGINS, "5"));

        Assessment a = RiskScorer.score(settings, establishedProfile(), familiar().withDevice(null));

        assertEquals(List.of(Reason.LEARNING), a.reasons());
    }

    @Test
    void anEmptyProfileIsLearning() {
        Assessment a = RiskScorer.score(defaults, new RiskProfile(), familiar());

        assertEquals(List.of(Reason.LEARNING), a.reasons());
    }
}
