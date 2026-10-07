package io.skycloak.keycloak.adaptiverisk.it;

import io.skycloak.keycloak.adaptiverisk.geoip.MmdbWriter;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * A Keycloak with the packaged extension jar in its providers directory.
 *
 * <p>By default a container of quay.io/keycloak/keycloak:${keycloak.image.version} is booted on
 * PostgreSQL, the database most production deployments use. Set the system property
 * keycloak.db=dev-file to boot it on Keycloak's embedded development database instead. Set
 * keycloak.url to run the tests against a Keycloak you started yourself with the jar installed,
 * the two headers and a GeoIP database configured as below, and admin/admin as bootstrap admin.
 */
final class KeycloakTestServer {

    static final String CLIENT_IP_HEADER = "X-Test-Client-IP";
    static final String COUNTRY_HEADER = "X-Test-Country";
    /** The fixture GeoIP database places this network in {@link #GEOIP_COUNTRY}. */
    static final String GEOIP_NETWORK = "198.51.100.0/24";
    static final String GEOIP_COUNTRY = "NZ";
    private static final String GEOIP_PATH = "/opt/keycloak/conf/country.mmdb";
    static final String ADMIN_USER = "admin";
    static final String ADMIN_PASSWORD = "admin";

    static final int DB_POOL_SIZE = 2;
    private static final String DB_NAME = "keycloak";
    private static final String DB_USER = "keycloak";
    private static final String DB_PASSWORD = "keycloak";

    private static String baseUrl;
    private static GenericContainer<?> keycloak;
    private static GenericContainer<?> postgres;

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
        keycloak = new GenericContainer<>("quay.io/keycloak/keycloak:" + version)
                .withCopyFileToContainer(MountableFile.forHostPath(jar), "/opt/keycloak/providers/keycloak-adaptive-risk.jar")
                .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", ADMIN_USER)
                .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
                .withEnv("SKYCLOAK_ADAPTIVE_RISK_CLIENT_IP_HEADER", CLIENT_IP_HEADER)
                .withEnv("SKYCLOAK_ADAPTIVE_RISK_COUNTRY_HEADER", COUNTRY_HEADER)
                .withCopyFileToContainer(MountableFile.forHostPath(geoIpDatabase(), 0644), GEOIP_PATH)
                .withEnv("SKYCLOAK_ADAPTIVE_RISK_GEOIP_DATABASE", GEOIP_PATH)
                .withExposedPorts(8080)
                .waitingFor(Wait.forHttp("/realms/master").forPort(8080).withStartupTimeout(Duration.ofMinutes(4)));
        // Newer 26.x dev mode binds to localhost only, unreachable through the mapped port.
        // A pool of two connections: enough for one login at a time, so a login that takes a second
        // connection stalls visibly when two run at once (see AdaptiveRiskIT).
        List<String> command = new ArrayList<>(List.of("start-dev", "--http-host=0.0.0.0", "--metrics-enabled=true",
                "--db-pool-max-size=" + DB_POOL_SIZE));
        if (usesPostgres()) {
            Network network = Network.newNetwork();
            postgres = new GenericContainer<>("postgres:16-alpine")
                    .withNetwork(network)
                    .withNetworkAliases("postgres")
                    .withEnv("POSTGRES_DB", DB_NAME)
                    .withEnv("POSTGRES_USER", DB_USER)
                    .withEnv("POSTGRES_PASSWORD", DB_PASSWORD)
                    .waitingFor(Wait.forLogMessage(".*database system is ready to accept connections.*", 2));
            postgres.start();
            keycloak.withNetwork(network);
            command.addAll(List.of("--db=postgres", "--db-url=jdbc:postgresql://postgres:5432/" + DB_NAME,
                    "--db-username=" + DB_USER, "--db-password=" + DB_PASSWORD));
        }
        keycloak.withCommand(command.toArray(String[]::new));
        keycloak.start();
        baseUrl = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);
        return baseUrl;
    }

    private static Path geoIpDatabase() {
        try {
            Path file = Files.createTempFile("adaptive-risk-country", ".mmdb");
            file.toFile().deleteOnExit();
            Files.write(file, new MmdbWriter(6, 28).sharedStrings()
                    .insert(GEOIP_NETWORK, MmdbWriter.countryRecord(GEOIP_COUNTRY))
                    .build());
            return file;
        } catch (Exception e) {
            throw new IllegalStateException("Could not write the fixture GeoIP database", e);
        }
    }

    /** True when the booted Keycloak runs on PostgreSQL, so tests can run SQL against it. */
    static boolean usesPostgres() {
        String external = System.getProperty("keycloak.url");
        if (external != null && !external.isBlank()) {
            return false;
        }
        String db = System.getProperty("keycloak.db", "postgres");
        return switch (db) {
            case "postgres" -> true;
            case "dev-file" -> false;
            default -> throw new IllegalArgumentException("keycloak.db must be postgres or dev-file, not " + db);
        };
    }

    /** Runs one SQL statement through psql in the database container and returns its output. */
    static String sql(String statement) throws Exception {
        var result = postgres.execInContainer("psql", "-U", DB_USER, "-d", DB_NAME, "-v", "ON_ERROR_STOP=1",
                "-tAc", statement);
        if (result.getExitCode() != 0) {
            throw new IllegalStateException("psql failed: " + result.getStderr());
        }
        return result.getStdout().trim();
    }

    /**
     * Locks a table exclusively from another database session for the given time, so every read of
     * it blocks. Returns once the lock is held; the lock goes when the returned future completes.
     */
    static CompletableFuture<String> lockTable(String table, int seconds) throws Exception {
        CompletableFuture<String> holder = CompletableFuture.supplyAsync(() -> {
            try {
                return sql("BEGIN; LOCK TABLE " + table + " IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(" + seconds + "); COMMIT;");
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        for (int i = 0; i < 100 && !"t".equals(sql("SELECT EXISTS (SELECT 1 FROM pg_locks l JOIN pg_class c ON c.oid = l.relation "
                + "WHERE c.relname = '" + table + "' AND l.mode = 'AccessExclusiveLock' AND l.granted)")); i++) {
            Thread.sleep(100);
        }
        return holder;
    }

    /** The container's log, for failure messages. Empty when running against an external Keycloak. */
    static String logs() {
        return keycloak == null ? "" : keycloak.getLogs();
    }
}
