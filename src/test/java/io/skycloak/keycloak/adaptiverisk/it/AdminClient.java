package io.skycloak.keycloak.adaptiverisk.it;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** The few admin REST calls the integration tests need, over plain HTTP. */
final class AdminClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final HttpClient http = HttpClient.newHttpClient();
    private final String baseUrl;

    AdminClient(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    void importRealm(String json) throws IOException, InterruptedException {
        HttpResponse<String> response = send(HttpRequest.newBuilder(URI.create(baseUrl + "/admin/realms"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json)));
        if (response.statusCode() != 201) {
            throw new IllegalStateException("Realm import returned " + response.statusCode() + ": " + response.body());
        }
    }

    void deleteRealm(String realm) throws IOException, InterruptedException {
        send(HttpRequest.newBuilder(URI.create(baseUrl + "/admin/realms/" + realm)).DELETE());
    }

    String userId(String realm, String username) throws IOException, InterruptedException {
        JsonNode users = json(get("/admin/realms/" + realm + "/users?exact=true&username="
                + URLEncoder.encode(username, StandardCharsets.UTF_8)));
        return users.get(0).get("id").asText();
    }

    void deleteUser(String realm, String userId) throws IOException, InterruptedException {
        HttpResponse<String> response = send(HttpRequest.newBuilder(
                URI.create(baseUrl + "/admin/realms/" + realm + "/users/" + userId)).DELETE());
        if (response.statusCode() != 204) {
            throw new IllegalStateException("User delete returned " + response.statusCode() + ": " + response.body());
        }
    }

    /**
     * Details of events of one type, newest first, from the admin events API. A null userId lists
     * the whole realm's events.
     */
    List<Map<String, String>> eventDetails(String realm, String userId, String type) throws IOException, InterruptedException {
        String user = userId == null ? "" : "&user=" + userId;
        JsonNode events = json(get("/admin/realms/" + realm + "/events?type=" + type + user + "&max=100"));
        List<Map<String, String>> details = new ArrayList<>();
        for (JsonNode event : events) {
            Map<String, String> map = new java.util.HashMap<>();
            event.path("details").fields().forEachRemaining(e -> map.put(e.getKey(), e.getValue().asText()));
            details.add(map);
        }
        return details;
    }

    private HttpResponse<String> get(String path) throws IOException, InterruptedException {
        HttpResponse<String> response = send(HttpRequest.newBuilder(URI.create(baseUrl + path)).GET());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("GET " + path + " returned " + response.statusCode() + ": " + response.body());
        }
        return response;
    }

    private HttpResponse<String> send(HttpRequest.Builder request) throws IOException, InterruptedException {
        request.header("Authorization", "Bearer " + token());
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** A fresh admin token per call: tests are short and this avoids expiry handling. */
    private String token() throws IOException, InterruptedException {
        String form = "grant_type=password&client_id=admin-cli&username=" + KeycloakTestServer.ADMIN_USER
                + "&password=" + KeycloakTestServer.ADMIN_PASSWORD;
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(
                        URI.create(baseUrl + "/realms/master/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Admin token returned " + response.statusCode() + ": " + response.body());
        }
        return json(response).get("access_token").asText();
    }

    private static JsonNode json(HttpResponse<String> response) throws IOException {
        return MAPPER.readTree(response.body());
    }
}
