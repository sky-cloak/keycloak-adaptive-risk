package io.skycloak.keycloak.adaptiverisk;

import java.util.List;
import java.util.stream.Collectors;

/** The result of scoring one login: a 0 to 100 score, its level, and the reasons that fired. */
public record Assessment(int score, RiskLevel level, List<Reason> reasons) {

    public Assessment {
        reasons = List.copyOf(reasons);
    }

    /** Fail-open result: low, with the evaluation_error reason so the fault is visible. */
    public static Assessment evaluationError() {
        return new Assessment(0, RiskLevel.LOW, List.of(Reason.EVALUATION_ERROR));
    }

    public boolean learning() {
        return reasons.contains(Reason.LEARNING);
    }

    public boolean failed() {
        return reasons.contains(Reason.EVALUATION_ERROR);
    }

    /** Comma-separated reason codes, as written to the risk_reasons event detail. */
    public String reasonCodes() {
        return reasons.stream().map(Reason::code).collect(Collectors.joining(","));
    }
}
