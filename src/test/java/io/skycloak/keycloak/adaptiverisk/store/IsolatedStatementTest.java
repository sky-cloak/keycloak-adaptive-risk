package io.skycloak.keycloak.adaptiverisk.store;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Savepoint;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IsolatedStatementTest {

    private final List<String> calls = new ArrayList<>();
    private final Savepoint savepoint = (Savepoint) Proxy.newProxyInstance(getClass().getClassLoader(),
            new Class<?>[]{Savepoint.class}, (p, m, a) -> null);

    /** A connection that records what is called on it; the statement throws the given error, if any. */
    private Connection connection(boolean autoCommit, SQLException onSavepoint, SQLException onExecute,
                                  SQLException onRelease) {
        PreparedStatement statement = (PreparedStatement) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{PreparedStatement.class}, (p, m, a) -> switch (m.getName()) {
                    case "setQueryTimeout" -> {
                        calls.add("timeout " + a[0]);
                        yield null;
                    }
                    case "executeUpdate" -> {
                        calls.add("execute");
                        if (onExecute != null) {
                            throw onExecute;
                        }
                        yield 3;
                    }
                    case "close" -> {
                        calls.add("close");
                        yield null;
                    }
                    default -> null;
                });
        Connection[] self = new Connection[1];
        self[0] = (Connection) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{Connection.class},
                (p, m, a) -> switch (m.getName()) {
                    case "unwrap" -> self[0];
                    case "getAutoCommit" -> autoCommit;
                    case "setSavepoint" -> {
                        calls.add("savepoint");
                        if (onSavepoint != null) {
                            throw onSavepoint;
                        }
                        yield savepoint;
                    }
                    case "prepareStatement" -> {
                        calls.add("prepare");
                        yield statement;
                    }
                    case "rollback" -> {
                        assertSame(savepoint, a[0], "rolls back to its own savepoint, never the whole transaction");
                        calls.add("rollback to savepoint");
                        yield null;
                    }
                    case "releaseSavepoint" -> {
                        calls.add("release");
                        if (onRelease != null) {
                            throw onRelease;
                        }
                        yield null;
                    }
                    default -> throw new UnsupportedOperationException(m.getName());
                });
        return self[0];
    }

    private IsolatedStatement.Outcome<Integer> run(Connection connection) {
        return IsolatedStatement.run(connection, "DELETE FROM T WHERE A = ?", 2,
                statement -> statement.setString(1, "a"), PreparedStatement::executeUpdate);
    }

    @Test
    void aStatementThatSucceedsRunsInsideAReleasedSavepointWithATimeout() {
        IsolatedStatement.Outcome<Integer> outcome = run(connection(false, null, null, null));

        assertEquals(IsolatedStatement.Status.OK, outcome.status());
        assertEquals(3, outcome.value());
        // The timeout is reset before close: H2 applies it to the whole session, not the statement.
        assertEquals(List.of("savepoint", "prepare", "timeout 2", "execute", "timeout 0", "close", "release"), calls);
    }

    @Test
    void aStatementThatFailsIsRolledBackToItsSavepointSoTheTransactionSurvives() {
        SQLException missing = new SQLException("relation does not exist", "42P01");

        IsolatedStatement.Outcome<Integer> outcome = run(connection(false, null, missing, null));

        assertEquals(IsolatedStatement.Status.FAILED, outcome.status());
        assertSame(missing, outcome.error());
        assertTrue(calls.contains("rollback to savepoint"), calls.toString());
    }

    @Test
    void withoutSavepointsTheStatementStillRunsUnisolated() {
        IsolatedStatement.Outcome<Integer> outcome = run(connection(false,
                new SQLException("setSavePoint not allowed while an XA transaction is active"), null, null));

        assertEquals(IsolatedStatement.Status.OK, outcome.status());
        assertFalse(outcome.isolated());
        assertTrue(calls.contains("execute"), calls.toString());
    }

    @Test
    void aRuntimeErrorWhileReadingTheResultStillRollsBackToTheSavepoint() {
        Connection connection = connection(false, null, null, null);

        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class, () ->
                IsolatedStatement.run(connection, "SELECT 1", 2, statement -> { }, statement -> {
                    throw new IllegalStateException("bad row");
                }));
        assertTrue(calls.contains("rollback to savepoint"), calls.toString());
        assertTrue(calls.contains("timeout 0"), calls.toString());
    }

    @Test
    void aZeroTimeoutIsNeverSet() {
        IsolatedStatement.run(connection(false, null, null, null), "DELETE FROM T", 0, statement -> { },
                PreparedStatement::executeUpdate);

        assertFalse(calls.stream().anyMatch(c -> c.startsWith("timeout")), calls.toString());
    }

    @Test
    void savepointsGoToThePhysicalConnectionUnderThePool() {
        Connection physical = connection(false, null, null, null);
        Connection pooled = (Connection) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{Connection.class},
                (p, m, a) -> switch (m.getName()) {
                    case "unwrap" -> physical;
                    // What Keycloak's pool does for an enlisted connection.
                    case "rollback", "setSavepoint", "prepareStatement" ->
                            throw new SQLException("Attempting to rollback while enlisted in a transaction");
                    default -> throw new UnsupportedOperationException(m.getName());
                });

        IsolatedStatement.Outcome<Integer> outcome = run(pooled);

        assertEquals(IsolatedStatement.Status.OK, outcome.status());
        assertTrue(calls.contains("savepoint") && calls.contains("execute"), calls.toString());
    }

    @Test
    void aPoolThatCannotUnwrapRunsOnThePooledConnection() {
        Connection physical = connection(false, null, null, null);
        Connection pooled = (Connection) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{Connection.class},
                (p, m, a) -> {
                    if (m.getName().equals("unwrap")) {
                        throw new SQLException("unwrap not supported");
                    }
                    return m.invoke(physical, a);
                });

        IsolatedStatement.Outcome<Integer> outcome = run(pooled);

        assertEquals(IsolatedStatement.Status.OK, outcome.status());
        assertTrue(outcome.isolated());
    }

    @Test
    void inAutoCommitModeNoSavepointIsNeeded() {
        IsolatedStatement.Outcome<Integer> outcome = run(connection(true, null, null, null));

        assertEquals(IsolatedStatement.Status.OK, outcome.status());
        assertEquals(List.of("prepare", "timeout 2", "execute", "timeout 0", "close"), calls);
    }

    @Test
    void databasesThatCannotReleaseASavepointStillSucceed() {
        IsolatedStatement.Outcome<Integer> outcome = run(connection(false, null, null,
                new SQLFeatureNotSupportedException("releaseSavepoint")));

        assertEquals(IsolatedStatement.Status.OK, outcome.status());
    }

    @Test
    void recognisesAMissingTableOnEveryCommonDatabase() {
        assertTrue(IsolatedStatement.isMissingTable(new SQLException("x", "42P01")), "PostgreSQL");
        assertTrue(IsolatedStatement.isMissingTable(new SQLException("x", "42S02")), "MySQL, MariaDB, SQL Server, H2");
        assertTrue(IsolatedStatement.isMissingTable(new SQLException("x", "S0002")), "older SQL Server drivers");
        assertTrue(IsolatedStatement.isMissingTable(new SQLException("x", "42000", 942)), "Oracle ORA-00942");
        assertFalse(IsolatedStatement.isMissingTable(new SQLException("database offline", "S1000", 942)),
                "942 means a missing table only on Oracle");
        assertTrue(IsolatedStatement.isMissingTable(new SQLException("x", "42102", 42102)), "H2 by error code");
        assertTrue(IsolatedStatement.isMissingTable(new SQLException("outer", "XX000", new SQLException("x", "42P01"))),
                "anywhere in the chain");

        assertFalse(IsolatedStatement.isMissingTable(new SQLException("canceling statement", "57014")), "timeout");
        assertFalse(IsolatedStatement.isMissingTable(new SQLException("deadlock", "40P01")));
        assertFalse(IsolatedStatement.isMissingTable(new SQLException("no state")));
    }
}
