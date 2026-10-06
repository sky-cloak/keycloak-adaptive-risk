package io.skycloak.keycloak.adaptiverisk;

import java.util.ArrayList;
import java.util.List;

/**
 * Scores one login against the user's profile. Pure: no Keycloak types, no I/O.
 *
 * <p>The score is the sum of the weights of the reasons that fired, capped at 100. While the
 * profile is learning, history reasons do not fire and the score is the learning score plus
 * recent_failures, which needs no history.
 */
public final class RiskScorer {

    private RiskScorer() {
    }

    public static Assessment score(RiskSettings settings, RiskProfile profile, LoginSignals login) {
        List<Reason> reasons = new ArrayList<>();
        int score;

        boolean learning = profile.loginCount() < settings.learningLogins();
        if (learning) {
            reasons.add(Reason.LEARNING);
            score = settings.learningScore();
        } else {
            score = 0;
            if (!profile.knowsDevice(login.deviceHash())) {
                reasons.add(Reason.NEW_DEVICE);
            }
            if (login.network() != null && !profile.knowsNetwork(login.network())) {
                reasons.add(Reason.NEW_NETWORK);
            }
            if (login.country() != null) {
                // A profile with no country yet (learned before the header was configured) has no
                // baseline to compare with.
                if (profile.hasCountries() && !profile.knowsCountry(login.country())) {
                    reasons.add(Reason.NEW_COUNTRY);
                }
                if (rapidCountryChange(settings, profile, login)) {
                    reasons.add(Reason.RAPID_COUNTRY_CHANGE);
                }
            }
        }

        if (recentFailures(settings, login)) {
            reasons.add(Reason.RECENT_FAILURES);
        }
        if (!learning && !profile.knowsHourNear(login.hourUtc())) {
            reasons.add(Reason.UNUSUAL_HOUR);
        }

        // A weight of 0 turns the reason off: it neither scores nor appears in the event.
        reasons.removeIf(reason -> reason.weighted() && settings.weight(reason) == 0);
        for (Reason reason : reasons) {
            score += settings.weight(reason);
        }
        score = Math.min(100, score);
        return new Assessment(score, settings.levelFor(score), reasons);
    }

    private static boolean rapidCountryChange(RiskSettings settings, RiskProfile profile, LoginSignals login) {
        String last = profile.lastCountry();
        if (last == null || last.equals(login.country())) {
            return false;
        }
        long sinceLast = login.timestamp() - profile.lastLoginAt();
        return sinceLast >= 0 && sinceLast <= settings.rapidCountryChangeWindow().toMillis();
    }

    private static boolean recentFailures(RiskSettings settings, LoginSignals login) {
        Failures failures = login.failures();
        if (failures == null || failures.count() < settings.failureCount()) {
            return false;
        }
        return login.timestamp() - failures.lastFailureAt() <= settings.failureWindow().toMillis();
    }
}
