package io.skycloak.keycloak.adaptiverisk;

import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * One evaluation, kept in authentication session notes between the evaluator, the condition and
 * the success callbacks, which can run in different HTTP requests.
 *
 * @param deviceId the device cookie value to set on success (the browser's own, or a new one)
 * @param network  network prefix of the login, recorded on success
 */
public record Evaluation(Outcome outcome, String userId, Assessment assessment, String country, String deviceId,
                         String network, int hourUtc) {

    private static final Logger log = Logger.getLogger(Evaluation.class);

    static final String NOTE_PREFIX = "skycloak.adaptive-risk.";
    static final String NOTE_OUTCOME = NOTE_PREFIX + "outcome";
    static final String NOTE_USER = NOTE_PREFIX + "user";
    static final String NOTE_SCORE = NOTE_PREFIX + "score";
    static final String NOTE_LEVEL = NOTE_PREFIX + "level";
    static final String NOTE_REASONS = NOTE_PREFIX + "reasons";
    static final String NOTE_COUNTRY = NOTE_PREFIX + "country";
    static final String NOTE_DEVICE = NOTE_PREFIX + "device";
    static final String NOTE_NETWORK = NOTE_PREFIX + "network";
    static final String NOTE_HOUR = NOTE_PREFIX + "hour";

    static final List<String> ALL_NOTES = List.of(NOTE_OUTCOME, NOTE_USER, NOTE_SCORE, NOTE_LEVEL, NOTE_REASONS,
            NOTE_COUNTRY, NOTE_DEVICE, NOTE_NETWORK, NOTE_HOUR);

    /** Event detail names. A contract: admins write SIEM rules and webhooks against them. */
    public static final String DETAIL_SCORE = "risk_score";
    public static final String DETAIL_LEVEL = "risk_level";
    public static final String DETAIL_REASONS = "risk_reasons";
    public static final String DETAIL_COUNTRY = "risk_country";
    /** risk_reasons of a login where no reason fired. */
    public static final String NO_REASONS = "none";

    /** Outcome label of the evaluations metric. */
    public enum Outcome {
        EVALUATED,
        LEARNING,
        SKIPPED,
        ERROR;

        public String code() {
            return name().toLowerCase(Locale.ROOT);
        }

        /** An errored evaluation skipped step-up, so its login must not teach the profile. */
        public boolean learns() {
            return this == EVALUATED || this == LEARNING;
        }
    }

    public static Outcome outcomeOf(Assessment assessment) {
        if (assessment.failed()) {
            return Outcome.ERROR;
        }
        return assessment.learning() ? Outcome.LEARNING : Outcome.EVALUATED;
    }

    /** Scores the login, failing open to low with evaluation_error on any exception. */
    public static Assessment assess(RiskSettings settings, Supplier<RiskProfile> profile, Supplier<LoginSignals> signals) {
        try {
            return RiskScorer.score(settings, profile.get(), signals.get());
        } catch (RuntimeException e) {
            log.debug("Adaptive risk scoring failed", e);
            return Assessment.evaluationError();
        }
    }

    /** Details added to the LOGIN or LOGIN_ERROR event. Never a user, device ID, IP or network. */
    public Map<String, String> eventDetails() {
        Map<String, String> details = new LinkedHashMap<>();
        details.put(DETAIL_SCORE, Integer.toString(assessment.score()));
        details.put(DETAIL_LEVEL, assessment.level().code());
        // Keycloak drops empty details, so a login with no reasons says so explicitly.
        details.put(DETAIL_REASONS, assessment.reasons().isEmpty() ? NO_REASONS : assessment.reasonCodes());
        if (country != null) {
            details.put(DETAIL_COUNTRY, country);
        }
        return details;
    }

    public Map<String, String> notes() {
        Map<String, String> notes = new LinkedHashMap<>();
        notes.put(NOTE_OUTCOME, outcome.code());
        notes.put(NOTE_USER, userId);
        notes.put(NOTE_SCORE, Integer.toString(assessment.score()));
        notes.put(NOTE_LEVEL, assessment.level().code());
        notes.put(NOTE_REASONS, assessment.reasonCodes());
        putIfPresent(notes, NOTE_COUNTRY, country);
        putIfPresent(notes, NOTE_DEVICE, deviceId);
        putIfPresent(notes, NOTE_NETWORK, network);
        notes.put(NOTE_HOUR, Integer.toString(hourUtc));
        return notes;
    }

    /** @return the evaluation stored in the notes, or null when none (or an unreadable one) is there. */
    public static Evaluation fromNotes(Function<String, String> note) {
        RiskLevel level = RiskLevel.fromCode(note.apply(NOTE_LEVEL));
        String outcomeCode = note.apply(NOTE_OUTCOME);
        if (level == null || outcomeCode == null) {
            return null;
        }
        try {
            Outcome outcome = Outcome.valueOf(outcomeCode.toUpperCase(Locale.ROOT));
            List<Reason> reasons = new ArrayList<>();
            String codes = note.apply(NOTE_REASONS);
            if (codes != null && !codes.isBlank()) {
                for (String code : codes.split(",")) {
                    reasons.add(Reason.valueOf(code.trim().toUpperCase(Locale.ROOT)));
                }
            }
            Assessment assessment = new Assessment(Integer.parseInt(note.apply(NOTE_SCORE)), level, reasons);
            return new Evaluation(outcome, note.apply(NOTE_USER), assessment, note.apply(NOTE_COUNTRY),
                    note.apply(NOTE_DEVICE), note.apply(NOTE_NETWORK), Integer.parseInt(note.apply(NOTE_HOUR)));
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static void putIfPresent(Map<String, String> notes, String key, String value) {
        if (value != null) {
            notes.put(key, value);
        }
    }
}
