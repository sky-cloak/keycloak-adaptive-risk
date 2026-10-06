package io.skycloak.keycloak.adaptiverisk.store;

import io.skycloak.keycloak.adaptiverisk.LoginSignals;
import io.skycloak.keycloak.adaptiverisk.RiskProfile;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.KeycloakModelUtils;

import java.time.Duration;
import java.util.List;

/** Reads and writes profiles through the Keycloak session's entity manager. */
public final class JpaProfileStore {

    private final EntityManager em;

    public JpaProfileStore(EntityManager em) {
        this.em = em;
    }

    public static JpaProfileStore of(KeycloakSession session) {
        return new JpaProfileStore(session.getProvider(JpaConnectionProvider.class).getEntityManager());
    }

    /** @return the user's profile, or an empty one when the user has none yet. One indexed read. */
    public RiskProfile load(String realmId, String userId) {
        RiskProfileEntity entity = find(realmId, userId, LockModeType.NONE);
        if (entity == null) {
            return new RiskProfile();
        }
        return RiskProfile.restore(entity.getLoginCount(), entity.getLastLoginAt(), entity.getHistory());
    }

    /**
     * Learns one successful login, creating the row on the user's first one. The read locks the
     * row until the transaction ends, so two concurrent logins of the same user merge their
     * history instead of the last commit overwriting the other one's.
     */
    public void recordSuccess(String realmId, String userId, LoginSignals login, Duration retention) {
        RiskProfileEntity entity = find(realmId, userId, LockModeType.PESSIMISTIC_WRITE);
        RiskProfile profile = entity == null
                ? new RiskProfile()
                : RiskProfile.restore(entity.getLoginCount(), entity.getLastLoginAt(), entity.getHistory());
        profile.recordSuccess(login, retention);
        if (entity == null) {
            entity = new RiskProfileEntity();
            entity.setId(KeycloakModelUtils.generateId());
            entity.setRealmId(realmId);
            entity.setUserId(userId);
            em.persist(entity);
        }
        entity.setLoginCount(profile.loginCount());
        entity.setLastLoginAt(profile.lastLoginAt());
        entity.setHistory(profile.historyJson());
    }

    public int deleteUser(String realmId, String userId) {
        return em.createNamedQuery(RiskProfileEntity.DELETE_BY_USER)
                .setParameter("realmId", realmId)
                .setParameter("userId", userId)
                .executeUpdate();
    }

    public int deleteRealm(String realmId) {
        return em.createNamedQuery(RiskProfileEntity.DELETE_BY_REALM)
                .setParameter("realmId", realmId)
                .executeUpdate();
    }

    private RiskProfileEntity find(String realmId, String userId, LockModeType lock) {
        // No row limit: the unique key allows at most one row, and a limit with a row lock is
        // rejected on some databases.
        List<RiskProfileEntity> rows = em.createNamedQuery(RiskProfileEntity.FIND_BY_USER, RiskProfileEntity.class)
                .setParameter("realmId", realmId)
                .setParameter("userId", userId)
                .setLockMode(lock)
                .getResultList();
        return rows.isEmpty() ? null : rows.get(0);
    }
}
