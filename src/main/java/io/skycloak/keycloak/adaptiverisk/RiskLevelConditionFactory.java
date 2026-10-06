package io.skycloak.keycloak.adaptiverisk;

import org.keycloak.Config;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class RiskLevelConditionFactory implements ConditionalAuthenticatorFactory {

    /** Stable contract: admins wire flows against it. Never change without a migration. */
    public static final String PROVIDER_ID = "skycloak-adaptive-risk-condition";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED,
    };

    private static final List<ProviderConfigProperty> CONFIG = ProviderConfigurationBuilder.create()
            .property()
            .name(RiskLevelCondition.CONFIG_LEVEL)
            .label("Risk level")
            .helpText("The level this condition compares the evaluated level with.")
            .type(ProviderConfigProperty.LIST_TYPE)
            .options(RiskLevel.LOW.code(), RiskLevel.MEDIUM.code(), RiskLevel.HIGH.code())
            .defaultValue(RiskLevelCondition.DEFAULT_LEVEL.code())
            .add()
            .property()
            .name(RiskLevelCondition.CONFIG_MATCH)
            .label("Match")
            .helpText("'at-least' matches this level and above; 'exactly' matches only this level.")
            .type(ProviderConfigProperty.LIST_TYPE)
            .options(RiskLevelCondition.MATCH_AT_LEAST, RiskLevelCondition.MATCH_EXACTLY)
            .defaultValue(RiskLevelCondition.MATCH_AT_LEAST)
            .add()
            .build();

    @Override
    public ConditionalAuthenticator getSingleton() {
        return RiskLevelCondition.SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Condition - risk level (Skycloak)";
    }

    @Override
    public String getHelpText() {
        return "Matches when the risk level set earlier in the flow by 'Adaptive Risk - Evaluate (Skycloak)' "
                + "is at least, or exactly, the configured level. Does not match when no evaluation ran.";
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
        // Nothing to configure.
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
