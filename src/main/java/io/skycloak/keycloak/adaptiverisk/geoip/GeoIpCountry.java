package io.skycloak.keycloak.adaptiverisk.geoip;

import io.skycloak.keycloak.adaptiverisk.Countries;
import io.skycloak.keycloak.adaptiverisk.Networks;
import org.jboss.logging.Logger;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;

/**
 * Looks up the country of a client address in a GeoIP database file in the MaxMind DB format,
 * such as DB-IP IP to Country Lite or MaxMind GeoLite2 Country. The operator supplies the file;
 * the extension ships none.
 *
 * <p>The file is read into memory at startup. After that, a lookup checks at most once a minute
 * whether the file changed and, if so, reads it again on a background thread, so a slow or hung
 * file system never holds up a login. A file that is missing, damaged or replaced by a damaged one
 * never fails a login: lookups give no country (or keep using the last good file) and the problem
 * is logged.
 */
public final class GeoIpCountry implements AutoCloseable {

    public static final String ENV_DATABASE = "SKYCLOAK_ADAPTIVE_RISK_GEOIP_DATABASE";
    static final long RELOAD_CHECK_MILLIS = 60_000;
    /**
     * Country databases are under 20 MB and GeoLite2 City under 100 MB. During a reload two copies
     * are on the heap, so refuse anything that could not fit twice.
     */
    static final long MAX_FILE_BYTES = 128L * 1024 * 1024;

    private static final Logger log = Logger.getLogger(GeoIpCountry.class);

    /** What identifies one version of the file: a copy finishing in the same second changes the size. */
    private record Version(long modified, long size) {
    }

    private record Loaded(MaxMindDbReader reader, Version version) {
    }

    private final Path path;
    private final LongSupplier clock;
    private final Executor reloads;
    private final AtomicBoolean reloadPending = new AtomicBoolean();
    private volatile Loaded current;
    private volatile long nextCheck;
    /** The last version that failed to load, so a bad file is reported once and not re-read. */
    private volatile Version failed;
    private volatile boolean unreadableReported;
    private volatile Version lookupFailureReported;

    /** @return the database named by the env var, or null when the env var is unset */
    public static GeoIpCountry fromEnv(Map<String, String> env) {
        String value = env.get(ENV_DATABASE);
        if (value == null || value.isBlank()) {
            return null;
        }
        Executor background = Executors.newSingleThreadExecutor(task -> {
            Thread thread = new Thread(task, "adaptive-risk-geoip-reload");
            thread.setDaemon(true);
            return thread;
        });
        // Monotonic, so a clock step never delays or bunches the checks.
        return new GeoIpCountry(Path.of(value.trim()), () -> System.nanoTime() / 1_000_000, background);
    }

    /**
     * @param clock   milliseconds from a monotonic source
     * @param reloads where reloads after the first run
     */
    GeoIpCountry(Path path, LongSupplier clock, Executor reloads) {
        this.path = path;
        this.clock = clock;
        this.reloads = reloads;
        this.nextCheck = clock.getAsLong() + RELOAD_CHECK_MILLIS;
        reload();
    }

    /** @return the ISO country code of an IP literal, or null when unknown. Never resolves host names. */
    public String country(String address) {
        scheduleReloadIfDue();
        Loaded loaded = current;
        byte[] ip = Networks.parse(address);
        if (loaded == null || ip == null) {
            return null;
        }
        try {
            return isoCode(loaded.reader().lookup(ip));
        } catch (RuntimeException | StackOverflowError | OutOfMemoryError e) {
            if (!loaded.version().equals(lookupFailureReported)) {
                lookupFailureReported = loaded.version();
                log.warnf("Adaptive risk GeoIP lookups in %s fail (%s: %s); those logins get no country", path,
                        e.getClass().getSimpleName(), e.getMessage());
            }
            return null;
        }
    }

    /**
     * Reads country.iso_code (the MaxMind and DB-IP layout), a top-level country string, or a
     * top-level country_code (flat layouts other providers use).
     */
    static String isoCode(Object record) {
        if (!(record instanceof Map<?, ?> map)) {
            return null;
        }
        Object country = map.get("country");
        if (country instanceof Map<?, ?> nested && nested.get("iso_code") instanceof String code) {
            return Countries.normalize(code);
        }
        if (country instanceof String code) {
            return Countries.normalize(code);
        }
        return map.get("country_code") instanceof String code ? Countries.normalize(code) : null;
    }

    /** Stops the background reload thread. */
    @Override
    public void close() {
        if (reloads instanceof ExecutorService service) {
            service.shutdownNow();
        }
    }

    private static String describeBuild(long epochSeconds) {
        try {
            return epochSeconds > 0 ? Instant.ofEpochSecond(epochSeconds).toString() : "unknown";
        } catch (RuntimeException e) {
            return "unknown";
        }
    }

    private void scheduleReloadIfDue() {
        long now = clock.getAsLong();
        if (now < nextCheck || !reloadPending.compareAndSet(false, true)) {
            return;
        }
        nextCheck = now + RELOAD_CHECK_MILLIS;
        try {
            reloads.execute(() -> {
                try {
                    reload();
                } finally {
                    reloadPending.set(false);
                }
            });
        } catch (RuntimeException | Error e) {
            // For example no thread could be started: try again at the next check.
            reloadPending.set(false);
        }
    }

    private void reload() {
        Version version;
        try {
            version = new Version(Files.getLastModifiedTime(path).toMillis(), Files.size(path));
            unreadableReported = false;
        } catch (Exception e) {
            if (!unreadableReported) {
                unreadableReported = true;
                log.warnf("Adaptive risk GeoIP database %s is not readable (%s); %s", path, e.getClass().getSimpleName(),
                        current == null ? "country lookups are off until it is" : "still using the copy loaded earlier");
            }
            return;
        }
        Loaded loaded = current;
        if ((loaded != null && loaded.version().equals(version)) || version.equals(failed)) {
            return;
        }
        try {
            if (version.size() > MAX_FILE_BYTES) {
                throw new MaxMindDbReader.InvalidDatabaseException(
                        "file is " + version.size() + " bytes, more than the " + MAX_FILE_BYTES + " allowed");
            }
            MaxMindDbReader reader = new MaxMindDbReader(Files.readAllBytes(path));
            String built = describeBuild(reader.buildEpoch());
            current = new Loaded(reader, version);
            failed = null;
            log.infof("Adaptive risk GeoIP database loaded: %s (%s, built %s)", path, reader.databaseType(), built);
        } catch (Exception | OutOfMemoryError e) {
            failed = version;
            log.warnf("Adaptive risk GeoIP database %s could not be loaded (%s: %s); %s", path,
                    e.getClass().getSimpleName(), e.getMessage(),
                    loaded == null ? "country lookups are off until it is fixed" : "still using the previous file");
        }
    }
}
