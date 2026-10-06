package io.skycloak.keycloak.adaptiverisk.it;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * A cookie jar driving Keycloak's browser flow over plain HTTP, the way a browser would: it loads
 * the login page, posts the form, and reports where the flow ended.
 */
final class Browser {

    static final String REDIRECT_URI = "http://localhost/callback";
    private static final String DEVICE_COOKIE = "SKYCLOAK_ADAPTIVE_RISK_DEVICE";
    private static final Pattern FORM_ACTION = Pattern.compile("<form[^>]*action=\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);

    /** Where a login attempt ended. */
    enum Outcome {
        /** Redirected back to the application with a code. */
        LOGGED_IN,
        /** Shown the OTP form. */
        OTP_FORM,
        /** Anything else, for example the error page of Deny access. */
        REFUSED
    }

    record Result(Outcome outcome, int status, String body, List<String> setCookies) {
    }

    /**
     * Cookie name to value. Kept by hand because Keycloak marks its own cookies Secure, and the JDK's
     * CookieManager never sends Secure cookies over the plain HTTP the tests use. Every request
     * goes to one realm, so paths do not matter.
     */
    private final Map<String, String> cookies = new LinkedHashMap<>();
    private final HttpClient http = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    private final String baseUrl;
    private final String clientIp;
    private final String country;

    Browser(String baseUrl, String clientIp, String country) {
        this.baseUrl = baseUrl;
        this.clientIp = clientIp;
        this.country = country;
    }

    /** Runs the browser flow from the authorization endpoint through the username/password form. */
    Result login(String realm, String username, String password) throws IOException, InterruptedException {
        String auth = baseUrl + "/realms/" + realm + "/protocol/openid-connect/auth?client_id=it-app&response_type=code"
                + "&scope=openid&state=it&redirect_uri=" + URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8);
        HttpResponse<String> page = send(HttpRequest.newBuilder(URI.create(auth)).GET());
        if (page.statusCode() != 200) {
            throw new IllegalStateException("Login page returned " + page.statusCode() + ": " + page.body());
        }
        HttpResponse<String> posted = send(HttpRequest.newBuilder(URI.create(formAction(page.body())))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form(Map.of("username", username, "password", password)))));
        return classify(posted);
    }

    /**
     * Ends the Keycloak session but keeps the device cookie, like a returning browser whose SSO
     * session expired. Without this the next login would be SSO and skip the forms.
     */
    void forgetSession() {
        cookies.keySet().removeIf(name -> !DEVICE_COOKIE.equals(name));
    }

    boolean hasDeviceCookie() {
        return cookies.containsKey(DEVICE_COOKIE);
    }

    private HttpResponse<String> send(HttpRequest.Builder request) throws IOException, InterruptedException {
        request.header("X-Test-Client-IP", clientIp);
        if (country != null) {
            request.header("X-Test-Country", country);
        }
        if (!cookies.isEmpty()) {
            request.header("Cookie", cookies.entrySet().stream()
                    .map(e -> e.getKey() + "=" + e.getValue())
                    .collect(Collectors.joining("; ")));
        }
        HttpResponse<String> response = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
        for (String setCookie : response.headers().allValues("Set-Cookie")) {
            String pair = setCookie.split(";", 2)[0];
            int eq = pair.indexOf('=');
            String name = pair.substring(0, eq).trim();
            String value = pair.substring(eq + 1).trim();
            String attributes = setCookie.toLowerCase(Locale.ROOT);
            if (value.isEmpty() || attributes.contains("max-age=0") || attributes.contains("expires=thu, 01 jan 1970")) {
                cookies.remove(name);
            } else {
                cookies.put(name, value);
            }
        }
        return response;
    }

    private static Result classify(HttpResponse<String> response) {
        List<String> setCookies = response.headers().allValues("Set-Cookie");
        String location = response.headers().firstValue("Location").orElse("");
        Outcome outcome;
        if (response.statusCode() == 302 && location.startsWith(REDIRECT_URI) && location.contains("code=")) {
            outcome = Outcome.LOGGED_IN;
        } else if (response.statusCode() == 200 && response.body().contains("name=\"otp\"")) {
            outcome = Outcome.OTP_FORM;
        } else {
            outcome = Outcome.REFUSED;
        }
        return new Result(outcome, response.statusCode(), response.body(), setCookies);
    }

    private static String formAction(String html) {
        Matcher m = FORM_ACTION.matcher(html);
        if (!m.find()) {
            throw new IllegalStateException("No form on the login page: " + html);
        }
        return m.group(1).replace("&amp;", "&");
    }

    private static String form(Map<String, String> fields) {
        return fields.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
    }
}
