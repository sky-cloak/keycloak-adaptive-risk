package io.skycloak.keycloak.adaptiverisk.store;

import org.jboss.logging.Logger;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Runs one SQL statement on the caller's own connection, inside a savepoint, with an optional
 * query timeout. On PostgreSQL a failed statement aborts the transaction it runs in; rolling back
 * to the savepoint undoes only this statement, so the login or removal around it carries on. Using
 * the caller's connection, rather than a transaction of its own, means the extension never needs a
 * second pooled connection per request.
 */
final class IsolatedStatement {

    enum Status {
        OK,
        /** The statement failed. When it was isolated, the transaction around it is intact. */
        FAILED
    }

    /**
     * @param isolated whether the transaction around the statement is intact: a savepoint protected
     *                 it (and, on failure, the rollback to it worked), or it ran in auto-commit mode
     */
    record Outcome<T>(Status status, T value, SQLException error, boolean isolated) {
    }

    @FunctionalInterface
    interface Binder {
        void bind(PreparedStatement statement) throws SQLException;
    }

    @FunctionalInterface
    interface Executor<T> {
        T execute(PreparedStatement statement) throws SQLException;
    }

    private static final Logger log = Logger.getLogger(IsolatedStatement.class);
    private static final AtomicBoolean WARNED_UNISOLATED = new AtomicBoolean();

    private IsolatedStatement() {
    }

    /**
     * @param timeoutSeconds the query timeout, or 0 for none
     */
    static <T> Outcome<T> run(Connection pooled, String sql, int timeoutSeconds, Binder binder, Executor<T> executor) {
        Connection connection = physical(pooled);
        // Without the physical connection, a pool wrapper may accept setSavepoint yet refuse
        // rollback(Savepoint) while enlisted, so no savepoint is taken.
        Savepoint savepoint = connection != null ? savepoint(connection) : null;
        if (connection == null) {
            connection = pooled;
        }
        boolean isolated = savepoint != null || autoCommit(connection);
        try {
            T value;
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                if (timeoutSeconds > 0) {
                    statement.setQueryTimeout(timeoutSeconds);
                }
                try {
                    binder.bind(statement);
                    value = executor.execute(statement);
                } finally {
                    if (timeoutSeconds > 0) {
                        // H2 applies the timeout to the whole session, not just this statement.
                        resetTimeout(statement);
                    }
                }
            }
            release(connection, savepoint);
            return new Outcome<>(Status.OK, value, null, isolated);
        } catch (SQLException e) {
            boolean intact = rollback(connection, savepoint, e) && isolated;
            return new Outcome<>(Status.FAILED, null, e, intact);
        } catch (RuntimeException e) {
            rollback(connection, savepoint, e);
            throw e;
        }
    }

    /**
     * Keycloak's pool (Agroal) refuses rollback(Savepoint) on a connection enlisted in a
     * transaction, so the savepoint and the statement go to the physical connection under it,
     * which is the one in the transaction.
     */
    /** @return the physical connection, or null when the pool cannot hand it out */
    private static Connection physical(Connection pooled) {
        try {
            return pooled.unwrap(Connection.class);
        } catch (SQLException | RuntimeException e) {
            return null;
        }
    }

    /** @return a savepoint, or null in auto-commit mode or when the connection allows none */
    private static Savepoint savepoint(Connection connection) {
        try {
            return connection.getAutoCommit() ? null : connection.setSavepoint();
        } catch (SQLException | RuntimeException e) {
            if (WARNED_UNISOLATED.compareAndSet(false, true)) {
                log.warnf("Adaptive risk cannot use savepoints on this connection (%s); its statements run unisolated, "
                        + "so on PostgreSQL a failing profile statement can fail the request", e.getMessage());
            }
            return null;
        }
    }

    private static boolean autoCommit(Connection connection) {
        try {
            return connection.getAutoCommit();
        } catch (SQLException | RuntimeException e) {
            return false;
        }
    }

    private static void resetTimeout(PreparedStatement statement) {
        try {
            statement.setQueryTimeout(0);
        } catch (SQLException ignored) {
            // The statement is closed next; only H2 keeps the timeout beyond it.
        }
    }

    /** SQL Server and Oracle do not implement releasing a savepoint; it then lives until the transaction ends. */
    private static void release(Connection connection, Savepoint savepoint) {
        if (savepoint == null) {
            return;
        }
        try {
            connection.releaseSavepoint(savepoint);
        } catch (SQLException ignored) {
            // Harmless: the savepoint goes when the transaction ends.
        }
    }

    /**
     * @return false when the rollback to the savepoint failed: the database may have rolled back
     *         the whole transaction (InnoDB does after a deadlock), so it is no longer intact
     */
    private static boolean rollback(Connection connection, Savepoint savepoint, Exception cause) {
        if (savepoint == null) {
            return true;
        }
        try {
            connection.rollback(savepoint);
            return true;
        } catch (SQLException rollback) {
            cause.addSuppressed(rollback);
            return false;
        }
    }

    /** True when the error, or one it wraps, says the table does not exist. */
    static boolean isMissingTable(SQLException error) {
        for (Throwable t = error; t != null; t = t.getCause()) {
            if (t instanceof SQLException e) {
                String state = e.getSQLState();
                if ("42P01".equals(state) || "42S02".equals(state) || "S0002".equals(state)
                        || ("42000".equals(state) && e.getErrorCode() == 942) || e.getErrorCode() == 42102) {
                    return true;
                }
            }
        }
        return false;
    }
}
