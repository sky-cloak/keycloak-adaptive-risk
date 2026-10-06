package io.skycloak.keycloak.adaptiverisk;

import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowCallbackFactory;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class AdaptiveRiskAuthenticatorFactory implements AuthenticationFlowCallbackFactory {

    /** Stable contract: admins wire flows against it. Never change without a migration. */
    public static final String PROVIDER_ID = "skycloak-adaptive-risk";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED,
    };

    private static final List<ProviderConfigProperty> CONFIG = buildConfig();

    private TrustedHeaders headers = TrustedHeaders.fromEnv(System.getenv());

    private static List<ProviderConfigProperty> buildConfig() {
        ProviderConfigurationBuilder builder = ProviderConfigurationBuilder.create();
        number(builder, RiskSettings.MEDIUM_THRESHOLD, "Medium threshold",
                "Scores at or above this (0 to 100) are medium.", RiskSettings.DEFAULT_MEDIUM_THRESHOLD);
        number(builder, RiskSettings.HIGH_THRESHOLD, "High threshold",
                "Scores at or above this (0 to 100) are high.", RiskSettings.DEFAULT_HIGH_THRESHOLD);
        number(builder, RiskSettings.LEARNING_LOGINS, "Learning logins",
                "Successful logins a user needs before history reasons fire.", RiskSettings.DEFAULT_LEARNING_LOGINS);
        number(builder, RiskSettings.LEARNING_SCORE, "Learning score",
                "Score of a login while the user's profile is learning (recent_failures is added on top).",
                RiskSettings.DEFAULT_LEARNING_SCORE);
        for (Reason reason : Reason.values()) {
            if (reason.weighted()) {
                number(builder, RiskSettings.weightKey(reason), "Weight: " + reason.code(),
                        "Points added when " + reason.code() + " fires. 0 turns the reason off.", reason.defaultWeight());
            }
        }
        number(builder, RiskSettings.FAILURE_COUNT, "Recent failures: count",
                "Failed attempts in Keycloak's brute force record that make recent_failures fire. "
                        + "Needs brute force detection on.", RiskSettings.DEFAULT_FAILURE_COUNT);
        number(builder, RiskSettings.FAILURE_WINDOW_MINUTES, "Recent failures: window (minutes)",
                "How recent the last failed attempt must be.", RiskSettings.DEFAULT_FAILURE_WINDOW_MINUTES);
        number(builder, RiskSettings.RAPID_COUNTRY_CHANGE_MINUTES, "Rapid country change: window (minutes)",
                "A country change within this time of the last successful login fires rapid_country_change.",
                RiskSettings.DEFAULT_RAPID_COUNTRY_CHANGE_MINUTES);
        number(builder, RiskSettings.RETENTION_DAYS, "Retention (days)",
                "Profile entries unseen for this long are dropped.", RiskSettings.DEFAULT_RETENTION_DAYS);
        return builder.build();
    }

    private static void number(ProviderConfigurationBuilder builder, String name, String label, String help, int dflt) {
        builder.property()
                .name(name)
                .label(label)
                .helpText(help + " Default " + dflt + ".")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(Integer.toString(dflt))
                .add();
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new AdaptiveRiskAuthenticator(session, headers);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Adaptive Risk - Evaluate (Skycloak)";
    }

    @Override
    public String getHelpText() {
        return "Scores the login from 0 to 100 against the user's own login history and stores low, medium or "
                + "high for 'Condition - risk level (Skycloak)'. Never challenges the user. Place it after the "
                + "step that identifies the user, inside a sub-flow.";
    }

    @Override
    public String getReferenceCategory() {
        return "adaptive-risk";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG;
    }

    @Override
    public void init(Config.Scope config) {
        headers = TrustedHeaders.fromEnv(System.getenv());
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Nothing to post-init.
    }

    @Override
    public void close() {
        // Stateless.
    }
}
