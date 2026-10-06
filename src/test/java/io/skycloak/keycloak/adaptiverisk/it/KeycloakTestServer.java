package io.skycloak.keycloak.adaptiverisk.it;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

/**
 * A Keycloak with the packaged extension jar in its providers directory.
 *
 * <p>By default a container of quay.io/keycloak/keycloak:${keycloak.image.version} is booted. Set
 * the system property keycloak.url to run the tests against a Keycloak you started yourself with
 * the jar installed, the two headers configured as below, and admin/admin as bootstrap admin.
 */
final class KeycloakTestServer {

    static final String CLIENT_IP_HEADER = "X-Test-Client-IP";
    static final String COUNTRY_HEADER = "X-Test-Country";
    static final String ADMIN_USER = "admin";
    static final String ADMIN_PASSWORD = "admin";

    private static String baseUrl;
    private static GenericContainer<?> container;

    private KeycloakTestServer() {
    }

    static synchronized String baseUrl() {
        if (baseUrl != null) {
            return baseUrl;
        }
        String external = System.getProperty("keycloak.url");
        if (external != null && !external.isBlank()) {
            baseUrl = external.replaceAll("/+$", "");
            return baseUrl;
        }
        Path jar = Path.of(System.getProperty("adaptive.risk.jar", "target/keycloak-adaptive-risk.jar"));
        if (!Files.exists(jar)) {
            throw new IllegalStateException("Build the jar first (mvn verify runs package before the ITs): " + jar);
        }
        String version = System.getProperty("keycloak.image.version", "26.2.5");
        container = new GenericContainer<>("quay.io/keycloak/keycloak:" + version)
                .withCopyFileToContainer(MountableFile.forHostPath(jar), "/opt/keycloak/providers/keycloak-adaptive-risk.jar")
                .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", ADMIN_USER)
                .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
                .withEnv("SKYCLOAK_ADAPTIVE_RISK_CLIENT_IP_HEADER", CLIENT_IP_HEADER)
                .withEnv("SKYCLOAK_ADAPTIVE_RISK_COUNTRY_HEADER", COUNTRY_HEADER)
                // Newer 26.x dev mode binds to localhost only, unreachable through the mapped port.
                .withCommand("start-dev", "--http-host=0.0.0.0", "--metrics-enabled=true")
                .withExposedPorts(8080)
                .waitingFor(Wait.forHttp("/realms/master").forPort(8080).withStartupTimeout(Duration.ofMinutes(4)));
        container.start();
        baseUrl = "http://" + container.getHost() + ":" + container.getMappedPort(8080);
        return baseUrl;
    }

    /** The container's log, for failure messages. Empty when running against an external Keycloak. */
    static String logs() {
        return container == null ? "" : container.getLogs();
    }
}
