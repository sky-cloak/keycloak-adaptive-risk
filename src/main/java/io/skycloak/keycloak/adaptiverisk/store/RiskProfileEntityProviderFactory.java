package io.skycloak.keycloak.adaptiverisk.store;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderEvent;

import java.util.List;

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
     * Deletes the profile rows of a removed user or realm in the removal's transaction, so they go
     * if and only if it commits. The delete is isolated by a savepoint: a missing table never blocks
     * the removal, and any other failure fails it cleanly instead of aborting it half way.
     */
    static void onEvent(ProviderEvent event) {
        if (event instanceof UserModel.UserRemovedEvent removed) {
            int rows = JpaProfileStore.of(removed.getKeycloakSession())
                    .deleteUser(removed.getRealm().getId(), removed.getUser().getId());
            log.debugf("Deleted %d adaptive risk profile(s) of a removed user (realm=%s)", rows, removed.getRealm().getName());
        } else if (event instanceof RealmModel.RealmRemovedEvent removed) {
            int rows = JpaProfileStore.of(removed.getKeycloakSession()).deleteRealm(removed.getRealm().getId());
            log.debugf("Deleted %d adaptive risk profile(s) of a removed realm (realm=%s)", rows, removed.getRealm().getName());
        }
    }

    @Override
    public void close() {
        // Stateless.
    }
}
