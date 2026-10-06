package io.skycloak.keycloak.adaptiverisk.it;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Boots Keycloak with the jar and drives real browser-flow logins over HTTP through the README's
 * recommended flow: the evaluator after username/password, high goes to Deny access, medium goes
 * to OTP for users who already have it.
 */
class AdaptiveRiskIT {

    private static final String HOME_IP = "203.0.113.10";
    private static final String HOME_COUNTRY = "CA";

    private static String baseUrl;
    private static AdminClient admin;
    /** Default settings: learning logins score 0. */
    private static String realm;
    /** Learning score 80: every first login is high. */
    private static String strictRealm;

    @BeforeAll
    static void importRealms() throws Exception {
        baseUrl = KeycloakTestServer.baseUrl();
        admin = new AdminClient(baseUrl);
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        realm = "adaptive-" + suffix;
        strictRealm = "adaptive-strict-" + suffix;
        admin.importRealm(realmJson(realm, 0));
        admin.importRealm(realmJson(strictRealm, 80));
    }

    @AfterAll
    static void deleteRealms() throws Exception {
        if (admin != null) {
            admin.deleteRealm(realm);
            admin.deleteRealm(strictRealm);
        }
    }

    @Test
    void learningLoginsPassWithoutStepUpThenAKnownBrowserStaysLow() throws Exception {
        Browser home = new Browser(baseUrl, HOME_IP, HOME_COUNTRY);

        for (int i = 1; i <= 3; i++) {
            Browser.Result learning = home.login(realm, "alice", "alice-password");
            assertEquals(Browser.Outcome.LOGGED_IN, learning.outcome(), () -> "learning login " + describe(learning));
            if (i == 1) {
                assertDeviceCookie(learning.setCookies());
            }
            home.forgetSession();
        }
        assertTrue(home.hasDeviceCookie());

        Browser.Result known = home.login(realm, "alice", "alice-password");

        assertEquals(Browser.Outcome.LOGGED_IN, known.outcome(), () -> describe(known));
        List<Map<String, String>> logins = admin.eventDetails(realm, admin.userId(realm, "alice"), "LOGIN");
        assertEquals(4, logins.size());
        Map<String, String> newest = logins.get(0);
        assertEquals("0", newest.get("risk_score"));
        assertEquals("low", newest.get("risk_level"));
        assertEquals("none", newest.get("risk_reasons"));
        assertEquals(HOME_COUNTRY, newest.get("risk_country"));
        for (Map<String, String> learning : logins.subList(1, 4)) {
            assertEquals("learning", learning.get("risk_reasons"));
            assertEquals("low", learning.get("risk_level"));
        }
        for (Map<String, String> details : logins) {
            assertNoPersonalData(details);
        }
    }

    @Test
    void aFreshBrowserAfterLearningGetsTheOtpFormAndAbandoningItTeachesNothing() throws Exception {
        Browser home = new Browser(baseUrl, HOME_IP, HOME_COUNTRY);
        for (int i = 1; i <= 3; i++) {
            Browser.Result learning = home.login(realm, "bob", "bob-password");
            assertEquals(Browser.Outcome.LOGGED_IN, learning.outcome(), () -> describe(learning));
            home.forgetSession();
        }

        Browser stranger = new Browser(baseUrl, HOME_IP, HOME_COUNTRY);
        Browser.Result stepUp = stranger.login(realm, "bob", "bob-password");

        assertEquals(Browser.Outcome.OTP_FORM, stepUp.outcome(), () -> describe(stepUp));

        // Abandon the OTP form and come back: the stranger's device was not learned.
        stranger.forgetSession();
        Browser.Result again = stranger.login(realm, "bob", "bob-password");
        assertEquals(Browser.Outcome.OTP_FORM, again.outcome(), () -> describe(again));

        // The known browser is still low.
        Browser.Result known = home.login(realm, "bob", "bob-password");
        assertEquals(Browser.Outcome.LOGGED_IN, known.outcome(), () -> describe(known));
        assertEquals(4, admin.eventDetails(realm, admin.userId(realm, "bob"), "LOGIN").size());
    }

    @Test
    void aConfiguredHighScoreIsDeniedAndTheErrorEventCarriesTheRisk() throws Exception {
        Browser browser = new Browser(baseUrl, HOME_IP, HOME_COUNTRY);

        Browser.Result denied = browser.login(strictRealm, "alice", "alice-password");

        assertEquals(Browser.Outcome.REFUSED, denied.outcome(), () -> describe(denied));
        String userId = admin.userId(strictRealm, "alice");
        assertEquals(0, admin.eventDetails(strictRealm, userId, "LOGIN").size());
        // Keycloak records Deny access errors without a user ID, so read the realm's errors and pick
        // alice's by the username Keycloak itself adds.
        List<Map<String, String>> errors = admin.eventDetails(strictRealm, null, "LOGIN_ERROR").stream()
                .filter(d -> "alice".equals(d.get("username")))
                .toList();
        assertEquals(1, errors.size());
        Map<String, String> details = errors.get(0);
        assertEquals("80", details.get("risk_score"));
        assertEquals("high", details.get("risk_level"));
        assertEquals("learning", details.get("risk_reasons"));
        assertEquals(HOME_COUNTRY, details.get("risk_country"));
        assertNoPersonalData(details);
    }

    @Test
    void deletingAUserWithAProfileSucceeds() throws Exception {
        String realmName = "adaptive-delete-" + UUID.randomUUID().toString().substring(0, 8);
        admin.importRealm(realmJson(realmName, 0));
        Browser browser = new Browser(baseUrl, HOME_IP, HOME_COUNTRY);
        Browser.Result login = browser.login(realmName, "alice", "alice-password");
        assertEquals(Browser.Outcome.LOGGED_IN, login.outcome(), () -> describe(login));

        // The profile rows go in the deleting transaction; a failure there would fail these calls.
        admin.deleteUser(realmName, admin.userId(realmName, "alice"));
        admin.deleteRealm(realmName);
    }

    private static void assertDeviceCookie(List<String> setCookies) {
        String cookie = setCookies.stream()
                .filter(c -> c.startsWith("SKYCLOAK_ADAPTIVE_RISK_DEVICE="))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No device cookie in " + setCookies));
        String lower = cookie.toLowerCase();
        assertTrue(lower.contains("httponly"), cookie);
        assertTrue(lower.contains("max-age=31536000"), cookie);
        assertTrue(cookie.contains("Path=/realms/" + realm + "/"), cookie);
        // Plain HTTP in the test, so not Secure.
        assertFalse(lower.contains("secure"), cookie);
    }

    private static void assertNoPersonalData(Map<String, String> details) {
        for (String key : List.of("risk_score", "risk_level", "risk_reasons", "risk_country")) {
            String value = details.getOrDefault(key, "");
            assertFalse(value.contains("@") || value.contains(HOME_IP) || value.contains("alice") || value.contains("bob"),
                    key + "=" + value);
        }
    }

    private static String describe(Browser.Result result) {
        String body = result.body();
        return "status " + result.status() + ", body: " + body.substring(0, Math.min(600, body.length()))
                + "\n--- Keycloak log tail ---\n" + tail(KeycloakTestServer.logs());
    }

    private static String tail(String logs) {
        return logs.length() <= 4000 ? logs : logs.substring(logs.length() - 4000);
    }

    private static String realmJson(String name, int learningScore) throws IOException {
        try (InputStream in = AdaptiveRiskIT.class.getResourceAsStream("/adaptive-risk-realm.json")) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8)
                    .replace("__REALM__", name)
                    .replace("__LEARNING_SCORE__", Integer.toString(learningScore));
        }
    }
}
