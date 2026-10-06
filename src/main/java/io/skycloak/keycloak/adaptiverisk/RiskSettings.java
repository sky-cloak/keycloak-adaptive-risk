package io.skycloak.keycloak.adaptiverisk;

import java.time.Duration;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;

/**
 * Per-execution scoring settings, read from the evaluator's execution config (gear icon).
 * Every missing, blank or unparseable value falls back to its documented default, so an
 * unconfigured evaluator scores with the defaults.
 */
public record RiskSettings(
        int mediumThreshold,
        int highThreshold,
        int learningLogins,
        int learningScore,
        Map<Reason, Integer> weights,
        int failureCount,
        Duration failureWindow,
        Duration rapidCountryChangeWindow,
        Duration retention) {

    public static final String MEDIUM_THRESHOLD = "medium-threshold";
    public static final String HIGH_THRESHOLD = "high-threshold";
    public static final String LEARNING_LOGINS = "learning-logins";
    public static final String LEARNING_SCORE = "learning-score";
    public static final String FAILURE_COUNT = "failure-count";
    public static final String FAILURE_WINDOW_MINUTES = "failure-window-minutes";
    public static final String RAPID_COUNTRY_CHANGE_MINUTES = "rapid-country-change-minutes";
    public static final String RETENTION_DAYS = "retention-days";

    public static final int DEFAULT_MEDIUM_THRESHOLD = 30;
    public static final int DEFAULT_HIGH_THRESHOLD = 60;
    public static final int DEFAULT_LEARNING_LOGINS = 3;
    public static final int DEFAULT_LEARNING_SCORE = 0;
    public static final int DEFAULT_FAILURE_COUNT = 3;
    public static final int DEFAULT_FAILURE_WINDOW_MINUTES = 60;
    public static final int DEFAULT_RAPID_COUNTRY_CHANGE_MINUTES = 120;
    public static final int DEFAULT_RETENTION_DAYS = 90;

    public RiskSettings {
        weights = Collections.unmodifiableMap(new EnumMap<>(weights));
    }

    /** Config key of a reason's weight, for example weight-new-device. */
    public static String weightKey(Reason reason) {
        return "weight-" + reason.code().replace('_', '-');
    }

    public static RiskSettings defaults() {
        return fromConfig(Map.of());
    }

    public static RiskSettings fromConfig(Map<String, String> config) {
        Map<String, String> c = config == null ? Map.of() : config;
        Map<Reason, Integer> weights = new EnumMap<>(Reason.class);
        for (Reason reason : Reason.values()) {
            if (reason.weighted()) {
                weights.put(reason, score(c.get(weightKey(reason)), reason.defaultWeight()));
            }
        }
        return new RiskSettings(
                score(c.get(MEDIUM_THRESHOLD), DEFAULT_MEDIUM_THRESHOLD),
                score(c.get(HIGH_THRESHOLD), DEFAULT_HIGH_THRESHOLD),
                count(c.get(LEARNING_LOGINS), DEFAULT_LEARNING_LOGINS),
                score(c.get(LEARNING_SCORE), DEFAULT_LEARNING_SCORE),
                weights,
                Math.max(1, count(c.get(FAILURE_COUNT), DEFAULT_FAILURE_COUNT)),
                Duration.ofMinutes(count(c.get(FAILURE_WINDOW_MINUTES), DEFAULT_FAILURE_WINDOW_MINUTES)),
                Duration.ofMinutes(count(c.get(RAPID_COUNTRY_CHANGE_MINUTES), DEFAULT_RAPID_COUNTRY_CHANGE_MINUTES)),
                Duration.ofDays(Math.max(1, count(c.get(RETENTION_DAYS), DEFAULT_RETENTION_DAYS))));
    }

    public int weight(Reason reason) {
        return weights.getOrDefault(reason, 0);
    }

    public RiskLevel levelFor(int score) {
        if (score >= highThreshold) {
            return RiskLevel.HIGH;
        }
        if (score >= mediumThreshold) {
            return RiskLevel.MEDIUM;
        }
        return RiskLevel.LOW;
    }

    /** A 0 to 100 value; out of range values are clamped. */
    private static int score(String value, int fallback) {
        return Math.min(100, count(value, fallback));
    }

    /** A non-negative value; negative values are clamped to 0. */
    private static int count(String value, int fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Math.max(0, Integer.parseInt(value.trim()));
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
