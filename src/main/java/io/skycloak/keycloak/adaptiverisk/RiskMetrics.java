package io.skycloak.keycloak.adaptiverisk;

import io.micrometer.core.instrument.Metrics;
import org.jboss.logging.Logger;

/** The skycloak_adaptive_risk_evaluations counter. A no-op when metrics are disabled. */
final class RiskMetrics {

    static final String METRIC = "skycloak_adaptive_risk_evaluations";
    /** Level tag of skipped evaluations, which have no level. */
    static final String NO_LEVEL = "none";

    private static final Logger log = Logger.getLogger(RiskMetrics.class);

    private RiskMetrics() {
    }

    static void count(Evaluation.Outcome outcome, RiskLevel level, String realm) {
        try {
            Metrics.counter(METRIC,
                    "level", level == null ? NO_LEVEL : level.code(),
                    "outcome", outcome.code(),
                    "realm", realm).increment();
        } catch (Throwable t) {
            // Metrics must never affect the login path.
            log.debugf("Adaptive risk metric increment failed: %s", t.getMessage());
        }
    }
}
