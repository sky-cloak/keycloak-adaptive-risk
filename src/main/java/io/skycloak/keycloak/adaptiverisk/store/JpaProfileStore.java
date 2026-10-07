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
    /** The row is locked by the read before it; the guard on the old values is belt and braces. */
    private static final String UPDATE = "UPDATE " + TABLE + " SET LOGIN_COUNT = ?, LAST_LOGIN_AT = ?, HISTORY = ?"
            + WHERE_USER + " AND LOGIN_COUNT = ? AND LAST_LOGIN_AT = ?";
    private static final String DELETE_USER = "DELETE FROM " + TABLE + WHERE_USER;
    private static final String DELETE_REALM = "DELETE FROM " + TABLE + " WHERE REALM_ID = ?";

    private static final Logger log = Logger.getLogger(JpaProfileStore.class);

    /** A profile statement failed. */
    public static final class ProfileStoreException extends RuntimeException {
        private final boolean transactionIntact;

        ProfileStoreException(String message, IsolatedStatement.Outcome<?> outcome) {
            super(message, outcome.error());
            this.transactionIntact = outcome.isolated();
        }

        /**
         * False when the failure may have broken the request's transaction (no savepoint, or the
         * rollback to it failed). The caller must then mark the transaction rollback-only rather
         * than let the rest of the request run on it.
         */
        public boolean transactionIntact() {
            return transactionIntact;
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
            throw new ProfileStoreException("profile read failed", read);
        }
        return read.value() == null ? new RiskProfile() : read.value().profile();
    }

    /**
     * Learns one successful login, in the login's own transaction, so a login that rolls back
     * teaches nothing. A user's first login inserts the row. A later login reads the row with a lock
     * (a record lock: a missing row is never locked, which on InnoDB would take a gap lock that
     * deadlocks two concurrent first logins), so it merges into the latest version on every
     * isolation level, and updates it. When two first logins race, the losing insert fails on the
     * unique key and that login is not learned; retrying after a duplicate key could deadlock on
     * InnoDB, and one learning login is a small price.
     *
     * @throws ProfileStoreException when the write failed
     */
    public void recordSuccess(String realmId, String userId, LoginSignals login, Duration retention) {
        Session session = session();
        IsolatedStatement.Outcome<Stored> exists = session.doReturningWork(connection ->
                read(connection, SELECT + WHERE_USER, realmId, userId));
        if (exists.status() == IsolatedStatement.Status.FAILED) {
            throw new ProfileStoreException("profile read failed", exists);
        }
        if (exists.value() == null) {
            RiskProfile profile = new RiskProfile();
            profile.recordSuccess(login, retention);
            IsolatedStatement.Outcome<Integer> inserted = session.doReturningWork(connection ->
                    IsolatedStatement.run(connection, INSERT, QUERY_TIMEOUT_SECONDS, statement -> {
                        statement.setString(1, KeycloakModelUtils.generateId());
                        statement.setString(2, realmId);
                        statement.setString(3, userId);
                        statement.setInt(4, profile.loginCount());
                        statement.setLong(5, profile.lastLoginAt());
                        statement.setString(6, profile.historyJson());
                    }, PreparedStatement::executeUpdate));
            if (inserted.status() == IsolatedStatement.Status.FAILED) {
                throw new ProfileStoreException("profile insert failed (a concurrent first login may have won)", inserted);
            }
            return;
        }

        IsolatedStatement.Outcome<Stored> locked = session.doReturningWork(connection ->
                read(connection, lockingSelect(productName(connection)), realmId, userId));
        if (locked.status() == IsolatedStatement.Status.FAILED) {
            throw new ProfileStoreException("profile read failed", locked);
        }
        Stored stored = locked.value();
        if (stored == null) {
            // Deleted since the first read, with its user: nothing to learn into.
            return;
        }
        RiskProfile profile = stored.profile();
        profile.recordSuccess(login, retention);
        IsolatedStatement.Outcome<Integer> updated = session.doReturningWork(connection ->
                IsolatedStatement.run(connection, UPDATE, QUERY_TIMEOUT_SECONDS, statement -> {
                    statement.setInt(1, profile.loginCount());
                    statement.setLong(2, profile.lastLoginAt());
                    statement.setString(3, profile.historyJson());
                    statement.setString(4, realmId);
                    statement.setString(5, userId);
                    statement.setInt(6, stored.loginCount());
                    statement.setLong(7, stored.lastLoginAt());
                }, PreparedStatement::executeUpdate));
        if (updated.status() == IsolatedStatement.Status.FAILED) {
            throw new ProfileStoreException("profile update failed", updated);
        }
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
        throw new ProfileStoreException("profile delete failed", outcome);
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
