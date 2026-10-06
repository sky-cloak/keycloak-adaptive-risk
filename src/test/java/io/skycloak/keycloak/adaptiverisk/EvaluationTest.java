package io.skycloak.keycloak.adaptiverisk;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

class EvaluationTest {

    private static final String DEVICE_ID = "Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF";

    private static Evaluation mediumFromFrance() {
        Assessment assessment = new Assessment(45, RiskLevel.MEDIUM, List.of(Reason.NEW_DEVICE, Reason.NEW_NETWORK));
        return new Evaluation(Evaluation.Outcome.EVALUATED, "user-id-1", assessment, "FR", DEVICE_ID,
                "203.0.113.0/24", 14);
    }

    @Test
    void eventDetailsCarryScoreLevelReasonsAndCountry() {
        assertEquals(Map.of(
                "risk_score", "45",
                "risk_level", "medium",
                "risk_reasons", "new_device,new_network",
                "risk_country", "FR"), mediumFromFrance().eventDetails());
    }

    @Test
    void eventDetailsOmitTheCountryWhenUnknown() {
        Evaluation e = new Evaluation(Evaluation.Outcome.LEARNING, "user-id-1",
                new Assessment(0, RiskLevel.LOW, List.of(Reason.LEARNING)), null, DEVICE_ID, null, 3);

        assertEquals(Map.of("risk_score", "0", "risk_level", "low", "risk_reasons", "learning"), e.eventDetails());
    }

    @Test
    void noReasonsIsWrittenAsNoneBecauseKeycloakDropsEmptyDetails() {
        Evaluation e = new Evaluation(Evaluation.Outcome.EVALUATED, "user-id-1",
                new Assessment(0, RiskLevel.LOW, List.of()), "CA", DEVICE_ID, null, 3);

        assertEquals("none", e.eventDetails().get("risk_reasons"));
        assertEquals(e, Evaluation.fromNotes(e.notes()::get));
    }

    @Test
    void eventDetailsNeverCarryDeviceNetworkOrUser() {
        String details = mediumFromFrance().eventDetails().toString();

        assertFalse(details.contains(DEVICE_ID));
        assertFalse(details.contains("203.0.113"));
        assertFalse(details.contains("user-id-1"));
    }

    @Test
    void roundTripsThroughAuthSessionNotes() {
        Map<String, String> notes = new HashMap<>(mediumFromFrance().notes());

        assertEquals(mediumFromFrance(), Evaluation.fromNotes(notes::get));
    }

    @Test
    void noNotesMeansNoEvaluation() {
        assertNull(Evaluation.fromNotes(Map.<String, String>of()::get));
        assertNull(Evaluation.fromNotes(Map.of(Evaluation.NOTE_LEVEL, "extreme")::get));
    }

    @Test
    void outcomeFollowsTheAssessment() {
        assertEquals(Evaluation.Outcome.EVALUATED, Evaluation.outcomeOf(mediumFromFrance().assessment()));
        assertEquals(Evaluation.Outcome.LEARNING,
                Evaluation.outcomeOf(new Assessment(0, RiskLevel.LOW, List.of(Reason.LEARNING))));
        assertEquals(Evaluation.Outcome.ERROR, Evaluation.outcomeOf(Assessment.evaluationError()));
    }

    @Test
    void failuresWhileReadingOrScoringFailOpenToLow() {
        Assessment readFails = Evaluation.assess(RiskSettings.defaults(),
                () -> { throw new IllegalStateException("database unavailable"); },
                () -> new LoginSignals(null, null, null, 0, 0L, null));
        Assessment signalsFail = Evaluation.assess(RiskSettings.defaults(),
                RiskProfile::new,
                () -> { throw new IllegalArgumentException("bad header"); });

        for (Assessment a : List.of(readFails, signalsFail)) {
            assertEquals(0, a.score());
            assertEquals(RiskLevel.LOW, a.level());
            assertEquals(List.of(Reason.EVALUATION_ERROR), a.reasons());
        }
    }

    @Test
    void onlyEvaluatedAndLearningLoginsTeachTheProfile() {
        assertEquals(true, Evaluation.Outcome.EVALUATED.learns());
        assertEquals(true, Evaluation.Outcome.LEARNING.learns());
        assertEquals(false, Evaluation.Outcome.ERROR.learns());
        assertEquals(false, Evaluation.Outcome.SKIPPED.learns());
    }
}
