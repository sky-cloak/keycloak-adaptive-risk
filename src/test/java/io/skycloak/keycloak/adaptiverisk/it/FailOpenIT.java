package io.skycloak.keycloak.adaptiverisk.it;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * A broken or slow profile table must never break a login. On PostgreSQL a failed statement
 * aborts the whole transaction it runs in, so these tests need the PostgreSQL-backed Keycloak.
 */
class FailOpenIT {

    private static final String TABLE = "skycloak_adaptive_risk_profile";
    private static final String HIDDEN = TABLE + "_hidden";

    private static String baseUrl;
    private static AdminClient admin;
    private static String realm;

    @BeforeAll
    static void importRealm() throws Exception {
        if (!KeycloakTestServer.usesPostgres()) {
            return;
        }
        baseUrl = KeycloakTestServer.baseUrl();
        admin = new AdminClient(baseUrl);
        realm = "adaptive-failopen-" + UUID.randomUUID().toString().substring(0, 8);
        admin.importRealm(realmJson(realm));
    }

    /** Per test, so the tests show as skipped rather than vanish on the embedded database. */
    @BeforeEach
    void needsPostgres() {
        assumeTrue(KeycloakTestServer.usesPostgres(), "needs the PostgreSQL-backed Keycloak");
    }

    @AfterAll
    static void deleteRealm() throws Exception {
        if (admin != null) {
            admin.deleteRealm(realm);
        }
    }

    @Test
    void aMissingProfileTableLetsTheLoginFinish() throws Exception {
        Browser browser = new Browser(baseUrl, "203.0.113.20", "CA");
        Browser.Result login;
        KeycloakTestServer.sql("ALTER TABLE " + TABLE + " RENAME TO " + HIDDEN);
        try {
            login = browser.login(realm, "alice", "alice-password");
        } finally {
            KeycloakTestServer.sql("ALTER TABLE " + HIDDEN + " RENAME TO " + TABLE);
        }

        assertEquals(Browser.Outcome.LOGGED_IN, login.outcome(), () -> describe(login));
        assertEquals(200, browser.exchangeCode(realm, login), "the code of a failed-open login must be redeemable");
        Map<String, String> details = lastLogin("alice");
        assertEquals("low", details.get("risk_level"));
        assertEquals("evaluation_error", details.get("risk_reasons"));
    }

    @Test
    void aLockedProfileTableFailsOpenInsteadOfHangingTheLogin() throws Exception {
        Browser browser = new Browser(baseUrl, "203.0.113.21", "CA");
        CompletableFuture<String> lock = KeycloakTestServer.lockTable(TABLE, 20);
        long started = System.nanoTime();
        Browser.Result login;
        long seconds;
        try {
            login = browser.login(realm, "bob", "bob-password");
            seconds = TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - started);
        } finally {
            lock.get(30, TimeUnit.SECONDS);
        }

        assertEquals(Browser.Outcome.LOGGED_IN, login.outcome(), () -> describe(login));
        assertTrue(seconds < 10, "the login waited " + seconds + "s on the locked table");
        assertEquals(200, browser.exchangeCode(realm, login));
        assertEquals("evaluation_error", lastLogin("bob").get("risk_reasons"));
    }

    @Test
    void deletingAUserSucceedsWhenTheProfileTableIsMissing() throws Exception {
        String userId = admin.userId(realm, "carol");
        KeycloakTestServer.sql("ALTER TABLE " + TABLE + " RENAME TO " + HIDDEN);
        try {
            admin.deleteUser(realm, userId);
        } finally {
            KeycloakTestServer.sql("ALTER TABLE " + HIDDEN + " RENAME TO " + TABLE);
        }
    }

    @Test
    void aLockedProfileTableFailsAUserDeletionFastInsteadOfLeavingItsProfileBehind() throws Exception {
        String userId = admin.userId(realm, "erin");
        CompletableFuture<String> lock = KeycloakTestServer.lockTable(TABLE, 20);
        long started = System.nanoTime();
        int status;
        long seconds;
        try {
            status = admin.deleteUserStatus(realm, userId);
            seconds = TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - started);
        } finally {
            lock.get(30, TimeUnit.SECONDS);
        }

        assertTrue(status >= 500, "the deletion must fail rather than orphan the profile, got " + status);
        assertTrue(seconds < 10, "the deletion waited " + seconds + "s on the locked table");
        // Nothing was half done: the user is still there, and deleting again works.
        assertEquals(userId, admin.userId(realm, "erin"));
        admin.deleteUser(realm, userId);
    }

    private static Map<String, String> lastLogin(String username) throws Exception {
        List<Map<String, String>> logins = admin.eventDetails(realm, admin.userId(realm, username), "LOGIN");
        assertTrue(!logins.isEmpty(), "no LOGIN event for " + username);
        return logins.get(0);
    }

    private static String describe(Browser.Result result) {
        String body = result.body();
        String logs = KeycloakTestServer.logs();
        return "status " + result.status() + ", body: " + body.substring(0, Math.min(600, body.length()))
                + "\n--- Keycloak log tail ---\n" + logs.substring(Math.max(0, logs.length() - 4000));
    }

    private static String realmJson(String name) throws IOException {
        try (InputStream in = FailOpenIT.class.getResourceAsStream("/adaptive-risk-realm.json")) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8)
                    .replace("__REALM__", name)
                    .replace("__LEARNING_SCORE__", "0");
        }
    }
}
