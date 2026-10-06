package io.skycloak.keycloak.adaptiverisk;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowCallbackFactory;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Map;
import java.util.ServiceLoader;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProviderRegistrationTest {

    private static Map<String, AuthenticatorFactory> authenticators() {
        return ServiceLoader.load(AuthenticatorFactory.class).stream()
                .filter(p -> p.type().getPackageName().startsWith("io.skycloak"))
                .map(ServiceLoader.Provider::get)
                .collect(Collectors.toMap(AuthenticatorFactory::getId, Function.identity()));
    }

    @Test
    void registersTheEvaluatorAndTheCondition() {
        Map<String, AuthenticatorFactory> factories = authenticators();

        AuthenticatorFactory evaluator = factories.get("skycloak-adaptive-risk");
        AuthenticatorFactory condition = factories.get("skycloak-adaptive-risk-condition");

        assertEquals("Adaptive Risk - Evaluate (Skycloak)", evaluator.getDisplayType());
        assertEquals("Condition - risk level (Skycloak)", condition.getDisplayType());
        // Learning relies on the flow callbacks; the condition must be recognised as one.
        assertInstanceOf(AuthenticationFlowCallbackFactory.class, evaluator);
        assertInstanceOf(ConditionalAuthenticatorFactory.class, condition);
        assertTrue(evaluator.isConfigurable());
        assertTrue(condition.isConfigurable());
    }

    @Test
    void registersTheProfileEntityAndChangelog() {
        JpaEntityProviderFactory factory = ServiceLoader.load(JpaEntityProviderFactory.class).stream()
                .filter(p -> p.type().getPackageName().startsWith("io.skycloak"))
                .findFirst().orElseThrow().get();

        assertEquals("skyrisk-profile", factory.getId());
        String changelog = factory.create(null).getChangelogLocation();
        assertNotNull(getClass().getClassLoader().getResource(changelog), changelog);
    }

    @Test
    void evaluatorConfigDefaultsAreTheScoringDefaults() {
        Map<String, String> defaults = authenticators().get("skycloak-adaptive-risk").getConfigProperties().stream()
                .collect(Collectors.toMap(ProviderConfigProperty::getName, p -> String.valueOf(p.getDefaultValue())));

        // Every scoring setting is in the gear dialog, and its pre-filled value scores like an empty config.
        assertEquals(14, defaults.size());
        assertEquals(RiskSettings.defaults(), RiskSettings.fromConfig(defaults));
        assertEquals("30", defaults.get("weight-new-device"));
    }
}
