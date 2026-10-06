package io.skycloak.keycloak.adaptiverisk;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.Map;

/**
 * 'Condition - risk level': matches when the level the evaluator stored earlier in this flow is at
 * least (default) or exactly the configured level. Admins put it in a conditional sub-flow in
 * front of OTP, WebAuthn or Deny access.
 */
public class RiskLevelCondition implements ConditionalAuthenticator {

    public static final String CONFIG_LEVEL = "risk-level";
    public static final String CONFIG_MATCH = "match";
    public static final String MATCH_AT_LEAST = "at-least";
    public static final String MATCH_EXACTLY = "exactly";
    public static final RiskLevel DEFAULT_LEVEL = RiskLevel.MEDIUM;

    static final RiskLevelCondition SINGLETON = new RiskLevelCondition();

    private static final Logger log = Logger.getLogger(RiskLevelCondition.class);

    /**
     * @param evaluated the level stored by the evaluator, or null when no evaluation ran
     * @param config    the condition's execution config, may be null
     */
    public static boolean matches(RiskLevel evaluated, Map<String, String> config) {
        if (evaluated == null) {
            return false;
        }
        Map<String, String> c = config == null ? Map.of() : config;
        RiskLevel configured = RiskLevel.fromCode(c.get(CONFIG_LEVEL));
        if (configured == null) {
            configured = DEFAULT_LEVEL;
        }
        boolean exactly = MATCH_EXACTLY.equalsIgnoreCase(trim(c.get(CONFIG_MATCH)));
        return exactly ? evaluated == configured : evaluated.atLeast(configured);
    }

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        RiskLevel evaluated = RiskLevel.fromCode(context.getAuthenticationSession().getAuthNote(Evaluation.NOTE_LEVEL));
        if (evaluated == null) {
            log.warnf("Condition - risk level reached, but no adaptive risk evaluation ran earlier in the flow; "
                    + "not matching. Put 'Adaptive Risk - Evaluate (Skycloak)' before it (realm=%s)",
                    context.getRealm().getName());
            return false;
        }
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        return matches(evaluated, config == null ? null : config.getConfig());
    }

    private static String trim(String value) {
        return value == null ? null : value.trim();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // A condition never challenges.
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required actions.
    }

    @Override
    public void close() {
        // Stateless.
    }
}
