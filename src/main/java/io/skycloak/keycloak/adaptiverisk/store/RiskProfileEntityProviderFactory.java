package io.skycloak.keycloak.adaptiverisk.store;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderEvent;

import java.util.List;
import java.util.function.ToIntFunction;

/**
 * Registers the profile entity and its Liquibase changelog with Keycloak, and deletes profile
 * rows when their user or realm is deleted.
 */
public class RiskProfileEntityProviderFactory implements JpaEntityProviderFactory {

    /**
     * Keycloak names the changelog table after the first ten letters of this ID
     * (DATABASECHANGELOG_SKYRISK_PR). Never change it: the changelog would run again.
     */
    public static final String PROVIDER_ID = "skyrisk-profile";
    static final String CHANGELOG = "META-INF/skycloak-adaptive-risk-changelog.xml";

    private static final Logger log = Logger.getLogger(RiskProfileEntityProviderFactory.class);

    private static final JpaEntityProvider PROVIDER = new JpaEntityProvider() {
        @Override
        public List<Class<?>> getEntities() {
            return List.of(RiskProfileEntity.class);
        }

        @Override
        public String getChangelogLocation() {
            return CHANGELOG;
        }

        @Override
        public String getFactoryId() {
            return PROVIDER_ID;
        }

        @Override
        public void close() {
            // Stateless.
        }
    };

    @Override
    public JpaEntityProvider create(KeycloakSession session) {
        return PROVIDER;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Config.Scope config) {
        // Nothing to configure.
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        factory.register(RiskProfileEntityProviderFactory::onEvent);
    }

    /**
     * Deletes the profile rows of a removed user or realm, in a transaction of their own: on
     * PostgreSQL a failing delete inside the removal's transaction (for example a missing table)
     * would abort the removal itself. If the removal later rolls back, the user only loses their
     * learned profile, which relearns.
     */
    static void onEvent(ProviderEvent event) {
        if (event instanceof UserModel.UserRemovedEvent removed) {
            String realmId = removed.getRealm().getId();
            String userId = removed.getUser().getId();
            delete(removed.getKeycloakSession().getKeycloakSessionFactory(), removed.getRealm().getName(), "user",
                    store -> store.deleteUser(realmId, userId));
        } else if (event instanceof RealmModel.RealmRemovedEvent removed) {
            String realmId = removed.getRealm().getId();
            delete(removed.getKeycloakSession().getKeycloakSessionFactory(), removed.getRealm().getName(), "realm",
                    store -> store.deleteRealm(realmId));
        }
    }

    private static void delete(KeycloakSessionFactory factory, String realmName, String what,
                               ToIntFunction<JpaProfileStore> deletion) {
        try {
            int rows = KeycloakModelUtils.runJobInTransactionWithResult(factory,
                    s -> deletion.applyAsInt(JpaProfileStore.of(s)));
            log.debugf("Deleted %d adaptive risk profile(s) of a removed %s (realm=%s)", rows, what, realmName);
        } catch (RuntimeException e) {
            log.warnf("Adaptive risk could not delete the profile(s) of a removed %s; the removal is unaffected: %s (realm=%s)",
                    what, e.getClass().getName(), realmName);
        }
    }

    @Override
    public void close() {
        // Stateless.
    }
}
