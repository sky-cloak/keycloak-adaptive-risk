package io.skycloak.keycloak.adaptiverisk.store;

import io.skycloak.keycloak.adaptiverisk.LoginSignals;
import io.skycloak.keycloak.adaptiverisk.RiskProfile;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import org.hibernate.Session;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.KeycloakModelUtils;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Duration;
import java.util.List;

/** Reads and writes profiles on the Keycloak session's connection. */
public final class JpaProfileStore {

    /**
     * Longest a profile statement may take before it fails, so a locked or overloaded table delays
     * a login or a removal by at most this much. Also bounds the wait for the row lock when a
     * successful login is recorded.
     */
    static final int QUERY_TIMEOUT_SECONDS = 2;
    private static final String QUERY_TIMEOUT_HINT = "jakarta.persistence.query.timeout";

    private static final String TABLE = "SKYCLOAK_ADAPTIVE_RISK_PROFILE";
    private static final String SELECT = "SELECT LOGIN_COUNT, LAST_LOGIN_AT, HISTORY FROM " + TABLE
            + " WHERE REALM_ID = ? AND USER_ID = ?";
    private static final String INSERT = "INSERT INTO " + TABLE
            + " (ID, REALM_ID, USER_ID, LOGIN_COUNT, LAST_LOGIN_AT, HISTORY) VALUES (?, ?, ?, ?, ?, ?)";
    /** Applies only if the row is unchanged since it was read: a concurrent login of the same user wins and is merged. */
    private static final String UPDATE = "UPDATE " + TABLE + " SET LOGIN_COUNT = ?, LAST_LOGIN_AT = ?, HISTORY = ?"
            + " WHERE REALM_ID = ? AND USER_ID = ? AND LOGIN_COUNT = ? AND LAST_LOGIN_AT = ?";
    private static final String DELETE_USER = "DELETE FROM " + TABLE + " WHERE REALM_ID = ? AND USER_ID = ?";
    private static final String DELETE_REALM = "DELETE FROM " + TABLE + " WHERE REALM_ID = ?";

    private static final Logger log = Logger.getLogger(JpaProfileStore.class);

    /** A profile statement failed; the transaction it ran in is intact. */
    public static final class ProfileStoreException extends RuntimeException {
        ProfileStoreException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** The connection cannot isolate a statement with a savepoint; the caller picks another way. */
    public static final class SavepointUnavailableException extends RuntimeException {
        SavepointUnavailableException(Throwable cause) {
            super("the connection does not allow a savepoint", cause);
        }
    }

    private final EntityManager em;

    public JpaProfileStore(EntityManager em) {
        this.em = em;
    }

    public static JpaProfileStore of(KeycloakSession session) {
        return new JpaProfileStore(session.getProvider(JpaConnectionProvider.class).getEntityManager());
    }

    /**
     * Reads the user's profile on the request's own connection, isolated by a savepoint, so a
     * failing or timed-out read leaves the login's transaction usable. One indexed read.
     *
     * @return the user's profile, or an empty one when the user has none yet
     * @throws ProfileStoreException         when the read failed
     * @throws SavepointUnavailableException when the connection allows no savepoint
     */
    public RiskProfile load(String realmId, String userId) {
        IsolatedStatement.Outcome<RiskProfile> outcome = em.unwrap(Session.class).doReturningWork(connection ->
                IsolatedStatement.run(connection, SELECT, QUERY_TIMEOUT_SECONDS, statement -> {
                    statement.setString(1, realmId);
                    statement.setString(2, userId);
                }, statement -> {
                    try (ResultSet row = statement.executeQuery()) {
                        return row.next()
                                ? RiskProfile.restore(row.getInt(1), row.getLong(2), row.getString(3))
                                : new RiskProfile();
                    }
                }));
        return switch (outcome.status()) {
            case OK -> outcome.value();
            case FAILED -> throw new ProfileStoreException("profile read failed", outcome.error());
            case NO_SAVEPOINT -> throw new SavepointUnavailableException(outcome.error());
        };
    }

    /**
     * Reads the profile through JPA, for a caller that runs it in a transaction of its own because
     * the request's connection allows no savepoint.
     */
    public RiskProfile loadWithJpa(String realmId, String userId) {
        RiskProfileEntity entity = find(realmId, userId, LockModeType.NONE);
        if (entity == null) {
            return new RiskProfile();
        }
        return RiskProfile.restore(entity.getLoginCount(), entity.getLastLoginAt(), entity.getHistory());
    }

    /**
     * Learns one successful login on the request's own connection, isolated by savepoints, so the
     * write needs no second pooled connection and a failed write leaves the login's transaction
     * usable. Concurrent logins of one user are merged optimistically: the update applies only if
     * the row is unchanged since it was read, otherwise the fresh row is read and merged once more.
     * Two first logins racing on the unique key end the same way.
     *
     * @throws ProfileStoreException         when the write failed or kept losing races
     * @throws SavepointUnavailableException when the connection allows no savepoint
     */
    public void recordSuccessOnRequestConnection(String realmId, String userId, LoginSignals login, Duration retention) {
        Session session = em.unwrap(Session.class);
        for (int attempt = 0; attempt < 2; attempt++) {
            IsolatedStatement.Outcome<Stored> read = session.doReturningWork(connection ->
                    IsolatedStatement.run(connection, SELECT, QUERY_TIMEOUT_SECONDS, statement -> {
                        statement.setString(1, realmId);
                        statement.setString(2, userId);
                    }, statement -> {
                        try (ResultSet row = statement.executeQuery()) {
                            return row.next() ? new Stored(row.getInt(1), row.getLong(2), row.getString(3)) : null;
                        }
                    }));
            if (read.status() == IsolatedStatement.Status.NO_SAVEPOINT) {
                throw new SavepointUnavailableException(read.error());
            }
            if (read.status() == IsolatedStatement.Status.FAILED) {
                throw new ProfileStoreException("profile read failed", read.error());
            }
            Stored stored = read.value();
            RiskProfile profile = stored == null
                    ? new RiskProfile()
                    : RiskProfile.restore(stored.loginCount(), stored.lastLoginAt(), stored.history());
            profile.recordSuccess(login, retention);

            IsolatedStatement.Outcome<Integer> written = session.doReturningWork(connection -> stored == null
                    ? IsolatedStatement.run(connection, INSERT, QUERY_TIMEOUT_SECONDS, statement -> {
                        statement.setString(1, KeycloakModelUtils.generateId());
                        statement.setString(2, realmId);
                        statement.setString(3, userId);
                        statement.setInt(4, profile.loginCount());
                        statement.setLong(5, profile.lastLoginAt());
                        statement.setString(6, profile.historyJson());
                    }, PreparedStatement::executeUpdate)
                    : IsolatedStatement.run(connection, UPDATE, QUERY_TIMEOUT_SECONDS, statement -> {
                        statement.setInt(1, profile.loginCount());
                        statement.setLong(2, profile.lastLoginAt());
                        statement.setString(3, profile.historyJson());
                        statement.setString(4, realmId);
                        statement.setString(5, userId);
                        statement.setInt(6, stored.loginCount());
                        statement.setLong(7, stored.lastLoginAt());
                    }, PreparedStatement::executeUpdate));
            switch (written.status()) {
                case OK -> {
                    if (written.value() == 1) {
                        return;
                    }
                    // The update hit no row: a concurrent login changed it. Read again and merge.
                }
                case NO_SAVEPOINT -> throw new SavepointUnavailableException(written.error());
                case FAILED -> {
                    if (stored != null) {
                        throw new ProfileStoreException("profile update failed", written.error());
                    }
                    // The insert failed, most likely on the unique key because a concurrent first
                    // login created the row. Read again and merge.
                }
            }
        }
        throw new ProfileStoreException("profile kept changing concurrently", null);
    }

    private record Stored(int loginCount, long lastLoginAt, String history) {
    }

    /**
     * Learns one successful login through JPA, for a caller that runs it in a transaction of its
     * own because the request's connection allows no savepoint. Creates the row on the user's
     * first login. The read locks the row until the transaction ends, so two concurrent logins of
     * the same user merge their history instead of the last commit overwriting the other one's.
     */
    public void recordSuccessWithJpa(String realmId, String userId, LoginSignals login, Duration retention) {
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

    /** Deletes a removed user's profile in the removal's transaction. See {@link #delete}. */
    public int deleteUser(String realmId, String userId) {
        return delete(DELETE_USER, RiskProfileEntity.DELETE_BY_USER, realmId, userId);
    }

    /** Deletes a removed realm's profiles in the removal's transaction. See {@link #delete}. */
    public int deleteRealm(String realmId) {
        return delete(DELETE_REALM, RiskProfileEntity.DELETE_BY_REALM, realmId, null);
    }

    /**
     * Deletes in the removal's own transaction, so the rows go if and only if the user or realm
     * goes. A missing table means there is nothing to delete, so it never blocks the removal. Any
     * other failure (a timeout on a locked table, for example) fails the removal, which the admin
     * can retry, rather than leave the profile behind.
     */
    private int delete(String sql, String namedQuery, String realmId, String userId) {
        IsolatedStatement.Outcome<Integer> outcome = em.unwrap(Session.class).doReturningWork(connection ->
                IsolatedStatement.run(connection, sql, QUERY_TIMEOUT_SECONDS, statement -> {
                    statement.setString(1, realmId);
                    if (userId != null) {
                        statement.setString(2, userId);
                    }
                }, PreparedStatement::executeUpdate));
        return switch (outcome.status()) {
            case OK -> outcome.value();
            case FAILED -> {
                if (IsolatedStatement.isMissingTable(outcome.error())) {
                    log.warnf("Adaptive risk profile table %s is missing; nothing to delete", TABLE);
                    yield 0;
                }
                throw new ProfileStoreException("profile delete failed", outcome.error());
            }
            case NO_SAVEPOINT -> {
                var query = em.createNamedQuery(namedQuery).setParameter("realmId", realmId);
                if (userId != null) {
                    query.setParameter("userId", userId);
                }
                yield query.executeUpdate();
            }
        };
    }

    private RiskProfileEntity find(String realmId, String userId, LockModeType lock) {
        // No row limit: the unique key allows at most one row, and a limit with a row lock is
        // rejected on some databases.
        List<RiskProfileEntity> rows = em.createNamedQuery(RiskProfileEntity.FIND_BY_USER, RiskProfileEntity.class)
                .setParameter("realmId", realmId)
                .setParameter("userId", userId)
                .setLockMode(lock)
                .setHint(QUERY_TIMEOUT_HINT, QUERY_TIMEOUT_SECONDS * 1000)
                .getResultList();
        return rows.isEmpty() ? null : rows.get(0);
    }
}
