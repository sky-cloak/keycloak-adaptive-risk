package io.skycloak.keycloak.adaptiverisk.store;

import io.skycloak.keycloak.adaptiverisk.LoginSignals;
import io.skycloak.keycloak.adaptiverisk.RiskProfile;
import jakarta.persistence.EntityManager;
import org.hibernate.Session;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.KeycloakModelUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;

/**
 * Reads and writes profiles with plain SQL on the connection of the Keycloak session's entity
 * manager, each statement isolated by {@link IsolatedStatement}.
 */
public final class JpaProfileStore {

    /**
     * Longest a per-login or per-user statement may take before it fails, so a locked or
     * overloaded table delays a login or a user removal by at most this much. A realm removal
     * deletes every profile of the realm and has no limit.
     */
    static final int QUERY_TIMEOUT_SECONDS = 2;
    private static final int NO_TIMEOUT = 0;

    private static final String TABLE = "SKYCLOAK_ADAPTIVE_RISK_PROFILE";
    private static final String SELECT = "SELECT LOGIN_COUNT, LAST_LOGIN_AT, HISTORY FROM " + TABLE;
    private static final String WHERE_USER = " WHERE REALM_ID = ? AND USER_ID = ?";
    private static final String INSERT = "INSERT INTO " + TABLE
            + " (ID, REALM_ID, USER_ID, LOGIN_COUNT, LAST_LOGIN_AT, HISTORY) VALUES (?, ?, ?, ?, ?, ?)";
    /** Applies only if the row is unchanged since it was read. */
    private static final String UPDATE = "UPDATE " + TABLE + " SET LOGIN_COUNT = ?, LAST_LOGIN_AT = ?, HISTORY = ?"
            + WHERE_USER + " AND LOGIN_COUNT = ? AND LAST_LOGIN_AT = ?";
    private static final String DELETE_USER = "DELETE FROM " + TABLE + WHERE_USER;
    private static final String DELETE_REALM = "DELETE FROM " + TABLE + " WHERE REALM_ID = ?";

    private static final Logger log = Logger.getLogger(JpaProfileStore.class);

    /** A profile statement failed. When it was isolated, the transaction it ran in is intact. */
    public static final class ProfileStoreException extends RuntimeException {
        ProfileStoreException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private record Stored(int loginCount, long lastLoginAt, String history) {
        RiskProfile profile() {
            return RiskProfile.restore(loginCount, lastLoginAt, history);
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
     * Reads the user's profile. One indexed read on the request's connection, isolated by a
     * savepoint, so a failing or timed-out read leaves the login's transaction usable.
     *
     * @return the user's profile, or an empty one when the user has none yet
     * @throws ProfileStoreException when the read failed
     */
    public RiskProfile load(String realmId, String userId) {
        IsolatedStatement.Outcome<Stored> read = session().doReturningWork(connection ->
                read(connection, SELECT + WHERE_USER, realmId, userId));
        if (read.status() == IsolatedStatement.Status.FAILED) {
            throw new ProfileStoreException("profile read failed", read.error());
        }
        return read.value() == null ? new RiskProfile() : read.value().profile();
    }

    /**
     * Learns one successful login, in the login's own transaction, so a login that rolls back
     * teaches nothing. The read locks the row, so it returns the latest version on every isolation
     * level and concurrent logins of one user queue. The update applies only if the row is
     * unchanged since the read; if a concurrent first login created the row first (the insert
     * fails on the unique key), the row is read again and merged once more.
     *
     * @throws ProfileStoreException when the write failed
     */
    public void recordSuccess(String realmId, String userId, LoginSignals login, Duration retention) {
        Session session = session();
        for (int attempt = 0; attempt < 2; attempt++) {
            IsolatedStatement.Outcome<Stored> read = session.doReturningWork(connection ->
                    read(connection, lockingSelect(productName(connection)), realmId, userId));
            if (read.status() == IsolatedStatement.Status.FAILED) {
                throw new ProfileStoreException("profile read failed", read.error());
            }
            Stored stored = read.value();
            RiskProfile profile = stored == null ? new RiskProfile() : stored.profile();
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
            if (written.status() == IsolatedStatement.Status.OK && written.value() == 1) {
                return;
            }
            if (written.status() == IsolatedStatement.Status.FAILED && (stored != null || !written.isolated())) {
                throw new ProfileStoreException("profile write failed", written.error());
            }
            // The insert lost a race with a concurrent first login, or the row changed after the
            // read: read again and merge.
        }
        throw new ProfileStoreException("profile kept changing concurrently", null);
    }

    /** Deletes a removed user's profile in the removal's transaction. See {@link #delete}. */
    public int deleteUser(String realmId, String userId) {
        return delete(DELETE_USER, QUERY_TIMEOUT_SECONDS, realmId, userId);
    }

    /** Deletes a removed realm's profiles in the removal's transaction, however many. See {@link #delete}. */
    public int deleteRealm(String realmId) {
        return delete(DELETE_REALM, NO_TIMEOUT, realmId, null);
    }

    /**
     * Deletes in the removal's own transaction, so the rows go if and only if the user or realm
     * goes. A missing table means there is nothing to delete, so it never blocks the removal. Any
     * other failure fails the removal, which the admin can retry, rather than leave the profile
     * behind.
     */
    private int delete(String sql, int timeoutSeconds, String realmId, String userId) {
        IsolatedStatement.Outcome<Integer> outcome = session().doReturningWork(connection ->
                IsolatedStatement.run(connection, sql, timeoutSeconds, statement -> {
                    statement.setString(1, realmId);
                    if (userId != null) {
                        statement.setString(2, userId);
                    }
                }, PreparedStatement::executeUpdate));
        if (outcome.status() == IsolatedStatement.Status.OK) {
            return outcome.value();
        }
        if (outcome.isolated() && IsolatedStatement.isMissingTable(outcome.error())) {
            log.warnf("Adaptive risk profile table %s is missing; nothing to delete", TABLE);
            return 0;
        }
        throw new ProfileStoreException("profile delete failed", outcome.error());
    }

    /**
     * The write's read, which locks the row. SQL Server has no FOR UPDATE and takes a lock hint
     * instead; it reads committed rows by default, which is all the merge needs.
     */
    static String lockingSelect(String productName) {
        if (productName != null && productName.startsWith("Microsoft SQL Server")) {
            return SELECT + " WITH (UPDLOCK, ROWLOCK)" + WHERE_USER;
        }
        return SELECT + WHERE_USER + " FOR UPDATE";
    }

    private static String productName(Connection connection) {
        try {
            return connection.getMetaData().getDatabaseProductName();
        } catch (SQLException | RuntimeException e) {
            return null;
        }
    }

    private static IsolatedStatement.Outcome<Stored> read(Connection connection, String sql, String realmId, String userId) {
        return IsolatedStatement.run(connection, sql, QUERY_TIMEOUT_SECONDS, statement -> {
            statement.setString(1, realmId);
            statement.setString(2, userId);
        }, statement -> {
            try (ResultSet row = statement.executeQuery()) {
                return row.next() ? new Stored(row.getInt(1), row.getLong(2), row.getString(3)) : null;
            }
        });
    }

    private Session session() {
        return em.unwrap(Session.class);
    }
}
