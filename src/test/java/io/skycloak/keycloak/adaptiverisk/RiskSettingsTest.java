package io.skycloak.keycloak.adaptiverisk;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RiskSettingsTest {

    @Test
    void defaultsArePinned() {
        // The README documents these values; changing one is a behavior change for every realm.
        RiskSettings s = RiskSettings.defaults();

        assertEquals(30, s.mediumThreshold());
        assertEquals(60, s.highThreshold());
        assertEquals(3, s.learningLogins());
        assertEquals(0, s.learningScore());
        assertEquals(3, s.failureCount());
        assertEquals(Duration.ofMinutes(60), s.failureWindow());
        assertEquals(Duration.ofMinutes(120), s.rapidCountryChangeWindow());
        assertEquals(Duration.ofDays(90), s.retention());
        assertEquals(30, s.weight(Reason.NEW_DEVICE));
        assertEquals(15, s.weight(Reason.NEW_NETWORK));
        assertEquals(30, s.weight(Reason.NEW_COUNTRY));
        assertEquals(40, s.weight(Reason.RAPID_COUNTRY_CHANGE));
        assertEquals(25, s.weight(Reason.RECENT_FAILURES));
        assertEquals(10, s.weight(Reason.UNUSUAL_HOUR));
        assertEquals(0, s.weight(Reason.LEARNING));
        assertEquals(0, s.weight(Reason.EVALUATION_ERROR));
    }

    @Test
    void configKeysAreStable() {
        assertEquals("weight-new-device", RiskSettings.weightKey(Reason.NEW_DEVICE));
        assertEquals("weight-rapid-country-change", RiskSettings.weightKey(Reason.RAPID_COUNTRY_CHANGE));
    }

    @Test
    void readsEveryConfiguredValue() {
        RiskSettings s = RiskSettings.fromConfig(Map.ofEntries(
                Map.entry("medium-threshold", "20"),
                Map.entry("high-threshold", "50"),
                Map.entry("learning-logins", "5"),
                Map.entry("learning-score", "40"),
                Map.entry("failure-count", "5"),
                Map.entry("failure-window-minutes", "15"),
                Map.entry("rapid-country-change-minutes", "240"),
                Map.entry("retention-days", "30"),
                Map.entry("weight-unusual-hour", " 0 ")));

        assertEquals(20, s.mediumThreshold());
        assertEquals(50, s.highThreshold());
        assertEquals(5, s.learningLogins());
        assertEquals(40, s.learningScore());
        assertEquals(5, s.failureCount());
        assertEquals(Duration.ofMinutes(15), s.failureWindow());
        assertEquals(Duration.ofMinutes(240), s.rapidCountryChangeWindow());
        assertEquals(Duration.ofDays(30), s.retention());
        assertEquals(0, s.weight(Reason.UNUSUAL_HOUR));
    }

    @Test
    void invalidValuesFallBackOrClamp() {
        RiskSettings s = RiskSettings.fromConfig(Map.of(
                "medium-threshold", "lots",
                "high-threshold", "250",
                "weight-new-device", "-5",
                "retention-days", "0"));

        assertEquals(30, s.mediumThreshold());
        assertEquals(100, s.highThreshold());
        assertEquals(0, s.weight(Reason.NEW_DEVICE));
        assertEquals(Duration.ofDays(1), s.retention());
    }

    @Test
    void nullConfigMeansDefaults() {
        assertEquals(RiskSettings.defaults(), RiskSettings.fromConfig(null));
    }
}
