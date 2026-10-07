package io.skycloak.keycloak.adaptiverisk.store;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Savepoint;

/**
 * Runs one SQL statement on the caller's own connection, inside a savepoint, with a query
 * timeout. On PostgreSQL a failed statement aborts the transaction it runs in; rolling back to the
 * savepoint undoes only this statement, so the login or removal around it carries on. Using the
 * caller's connection, rather than a transaction of its own, means the extension never needs a
 * second pooled connection per request.
 */
final class IsolatedStatement {

    enum Status {
        OK,
        /** The statement failed and was rolled back to the savepoint; the transaction is intact. */
        FAILED,
        /** The connection refused a savepoint (for example inside an XA transaction); nothing ran. */
        NO_SAVEPOINT
    }

    record Outcome<T>(Status status, T value, SQLException error) {
    }

    @FunctionalInterface
    interface Binder {
        void bind(PreparedStatement statement) throws SQLException;
    }

    @FunctionalInterface
    interface Executor<T> {
        T execute(PreparedStatement statement) throws SQLException;
    }

    private IsolatedStatement() {
    }

    static <T> Outcome<T> run(Connection pooled, String sql, int timeoutSeconds, Binder binder, Executor<T> executor) {
        Connection connection;
        Savepoint savepoint;
        try {
            // Keycloak's pool (Agroal) refuses rollback(Savepoint) on a connection enlisted in a
            // transaction, so the savepoint and the statement go to the physical connection under it,
            // which is the one in the transaction. Pools without unwrap support fall back below.
            connection = pooled.unwrap(Connection.class);
            savepoint = connection.getAutoCommit() ? null : connection.setSavepoint();
        } catch (SQLException e) {
            return new Outcome<>(Status.NO_SAVEPOINT, null, e);
        }
        try {
            T value;
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setQueryTimeout(timeoutSeconds);
                binder.bind(statement);
                value = executor.execute(statement);
            }
            release(connection, savepoint);
            return new Outcome<>(Status.OK, value, null);
        } catch (SQLException e) {
            if (savepoint != null) {
                try {
                    connection.rollback(savepoint);
                } catch (SQLException rollback) {
                    e.addSuppressed(rollback);
                }
            }
            return new Outcome<>(Status.FAILED, null, e);
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

    /** True when the error, or one it wraps, says the table does not exist. */
    static boolean isMissingTable(SQLException error) {
        for (Throwable t = error; t != null; t = t.getCause()) {
            if (t instanceof SQLException e) {
                String state = e.getSQLState();
                if ("42P01".equals(state) || "42S02".equals(state) || "S0002".equals(state)
                        || e.getErrorCode() == 942 || e.getErrorCode() == 42102) {
                    return true;
                }
            }
        }
        return false;
    }
}
