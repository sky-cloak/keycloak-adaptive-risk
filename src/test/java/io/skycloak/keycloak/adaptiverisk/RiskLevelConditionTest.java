package io.skycloak.keycloak.adaptiverisk;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RiskLevelConditionTest {

    private static final Map<String, String> MEDIUM_AT_LEAST = Map.of("risk-level", "medium");
    private static final Map<String, String> MEDIUM_EXACTLY = Map.of("risk-level", "medium", "match", "exactly");

    @Test
    void atLeastIsTheDefault() {
        assertFalse(RiskLevelCondition.matches(RiskLevel.LOW, MEDIUM_AT_LEAST));
        assertTrue(RiskLevelCondition.matches(RiskLevel.MEDIUM, MEDIUM_AT_LEAST));
        assertTrue(RiskLevelCondition.matches(RiskLevel.HIGH, MEDIUM_AT_LEAST));
    }

    @Test
    void exactlyMatchesOnlyThatLevel() {
        assertFalse(RiskLevelCondition.matches(RiskLevel.LOW, MEDIUM_EXACTLY));
        assertTrue(RiskLevelCondition.matches(RiskLevel.MEDIUM, MEDIUM_EXACTLY));
        assertFalse(RiskLevelCondition.matches(RiskLevel.HIGH, MEDIUM_EXACTLY));
    }

    @Test
    void highAtLeastMatchesOnlyHigh() {
        Map<String, String> high = Map.of("risk-level", "high", "match", "at-least");

        assertFalse(RiskLevelCondition.matches(RiskLevel.MEDIUM, high));
        assertTrue(RiskLevelCondition.matches(RiskLevel.HIGH, high));
    }

    @Test
    void unconfiguredConditionGatesMediumAndAbove() {
        assertFalse(RiskLevelCondition.matches(RiskLevel.LOW, null));
        assertTrue(RiskLevelCondition.matches(RiskLevel.MEDIUM, Map.of()));
    }

    @Test
    void noEvaluationNeverMatches() {
        assertFalse(RiskLevelCondition.matches(null, Map.of("risk-level", "low")));
    }
}
