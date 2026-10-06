package io.skycloak.keycloak.adaptiverisk;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RiskProfileTest {

    private static final long T0 = 1_780_000_000_000L;
    private static final long MINUTE = 60_000L;
    private static final Duration RETENTION = Duration.ofDays(90);

    private static LoginSignals login(String device, String network, String country, int hour, long at) {
        return new LoginSignals(device, network, country, hour, at, null);
    }

    @Test
    void recordsDeviceNetworkCountryAndHour() {
        RiskProfile profile = new RiskProfile();

        profile.recordSuccess(login("d1", "203.0.113.0/24", "CA", 9, T0), RETENTION);

        assertEquals(1, profile.loginCount());
        assertEquals(T0, profile.lastLoginAt());
        assertEquals("CA", profile.lastCountry());
        assertTrue(profile.knowsDevice("d1"));
        assertTrue(profile.knowsNetwork("203.0.113.0/24"));
        assertTrue(profile.knowsCountry("CA"));
        assertTrue(profile.knowsHourNear(9));
        assertFalse(profile.knowsDevice("d2"));
    }

    @Test
    void aLoginWithUnknownCountryClearsTheLastCountry() {
        RiskProfile profile = new RiskProfile();
        profile.recordSuccess(login("d1", null, "CA", 9, T0), RETENTION);

        profile.recordSuccess(login("d1", null, null, 9, T0 + MINUTE), RETENTION);

        assertNull(profile.lastCountry());
        assertTrue(profile.knowsCountry("CA"));
    }

    @Test
    void devicesAreCappedAt20EvictingTheLeastRecentlySeen() {
        RiskProfile profile = new RiskProfile();
        for (int i = 0; i < 20; i++) {
            profile.recordSuccess(login("d" + i, null, null, 9, T0 + i * MINUTE), RETENTION);
        }
        // Seeing d0 again makes d1 the least recently seen.
        profile.recordSuccess(login("d0", null, null, 9, T0 + 30 * MINUTE), RETENTION);

        profile.recordSuccess(login("d20", null, null, 9, T0 + 31 * MINUTE), RETENTION);

        assertEquals(20, profile.deviceCount());
        assertTrue(profile.knowsDevice("d0"));
        assertFalse(profile.knowsDevice("d1"));
        assertTrue(profile.knowsDevice("d20"));
    }

    @Test
    void networksAreCappedAt50AndCountriesAt20() {
        RiskProfile profile = new RiskProfile();
        for (int i = 0; i < 60; i++) {
            profile.recordSuccess(login(null, "10.0." + i + ".0/24", "C" + i, 9, T0 + i * MINUTE), RETENTION);
        }

        assertEquals(50, profile.networkCount());
        assertEquals(20, profile.countryCount());
        assertFalse(profile.knowsNetwork("10.0.9.0/24"));
        assertTrue(profile.knowsNetwork("10.0.10.0/24"));
        assertFalse(profile.knowsCountry("C39"));
        assertTrue(profile.knowsCountry("C40"));
    }

    @Test
    void entriesUnseenForTheRetentionAreDroppedOnWrite() {
        RiskProfile profile = new RiskProfile();
        profile.recordSuccess(login("old", "198.51.100.0/24", "FR", 3, T0), RETENTION);
        profile.recordSuccess(login("kept", "203.0.113.0/24", "CA", 9, T0 + Duration.ofDays(10).toMillis()), RETENTION);

        profile.recordSuccess(login("new", null, null, 15, T0 + Duration.ofDays(91).toMillis()), RETENTION);

        assertFalse(profile.knowsDevice("old"));
        assertFalse(profile.knowsNetwork("198.51.100.0/24"));
        assertFalse(profile.knowsCountry("FR"));
        assertFalse(profile.knowsHourNear(3));
        assertTrue(profile.knowsDevice("kept"));
        assertTrue(profile.knowsCountry("CA"));
        assertTrue(profile.knowsHourNear(9));
        assertEquals(3, profile.loginCount());
    }

    @Test
    void historyRoundTripsThroughJson() {
        RiskProfile profile = new RiskProfile();
        for (int i = 0; i < 25; i++) {
            profile.recordSuccess(login("d" + i, "10.0." + i + ".0/24", "CA", i % 24, T0 + i * MINUTE), RETENTION);
        }

        RiskProfile restored = RiskProfile.restore(profile.loginCount(), profile.lastLoginAt(), profile.historyJson());

        assertEquals(25, restored.loginCount());
        assertEquals(profile.lastLoginAt(), restored.lastLoginAt());
        assertEquals("CA", restored.lastCountry());
        assertEquals(20, restored.deviceCount());
        assertTrue(restored.knowsDevice("d24"));
        assertTrue(restored.knowsNetwork("10.0.0.0/24"));
        // Order survives, so the next write still evicts the least recently seen.
        restored.recordSuccess(login("d25", null, null, 9, T0 + 40 * MINUTE), RETENTION);
        assertFalse(restored.knowsDevice("d5"));
        assertTrue(restored.knowsDevice("d6"));
    }

    @Test
    void historyNeverContainsMoreThanWhatWasRecorded() {
        RiskProfile profile = new RiskProfile();
        profile.recordSuccess(login("3f2a", "203.0.113.0/24", "CA", 9, T0), RETENTION);

        String json = profile.historyJson();

        assertEquals("{\"lastCountry\":\"CA\",\"devices\":{\"3f2a\":" + T0 + "},\"networks\":{\"203.0.113.0/24\":" + T0
                + "},\"countries\":{\"CA\":" + T0 + "},\"hours\":{\"9\":" + T0 + "}}", json);
    }

    @Test
    void restoringWithoutHistoryKeepsTheCounters() {
        RiskProfile restored = RiskProfile.restore(4, T0, null);

        assertEquals(4, restored.loginCount());
        assertEquals(0, restored.deviceCount());
    }

    @Test
    void corruptHistoryIsAnError() {
        assertThrows(IllegalStateException.class, () -> RiskProfile.restore(4, T0, "{not json"));
    }
}
