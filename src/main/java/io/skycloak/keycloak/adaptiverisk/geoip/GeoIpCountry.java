package io.skycloak.keycloak.adaptiverisk.geoip;

import io.skycloak.keycloak.adaptiverisk.Countries;
import io.skycloak.keycloak.adaptiverisk.Networks;
import org.jboss.logging.Logger;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import java.util.function.LongSupplier;

/**
 * Looks up the country of a client address in a GeoIP database file in the MaxMind DB format,
 * such as DB-IP IP to Country Lite or MaxMind GeoLite2 Country. The operator supplies the file;
 * the extension ships none.
 *
 * <p>The file is read into memory at startup and read again when it changes, checked at most once
 * a minute, so it can be updated in place without a restart. A file that is missing, damaged or
 * replaced by a damaged one never fails a login: lookups give no country (or keep using the last
 * good file) and the problem is logged.
 */
public final class GeoIpCountry {

    public static final String ENV_DATABASE = "SKYCLOAK_ADAPTIVE_RISK_GEOIP_DATABASE";
    static final long RELOAD_CHECK_MILLIS = 60_000;
    /** Country databases are under 20 MB; refuse anything absurd rather than exhaust the heap. */
    static final long MAX_FILE_BYTES = 512L * 1024 * 1024;

    private static final Logger log = Logger.getLogger(GeoIpCountry.class);

    private record Loaded(MaxMindDbReader reader, long modified) {
    }

    private final Path path;
    private final LongSupplier clock;
    private volatile Loaded current;
    private volatile long nextCheck;
    /** Modification time of the last file that failed to load, so a bad file is reported once. */
    private long failedModified = Long.MIN_VALUE;

    /** @return the database named by the env var, or null when the env var is unset */
    public static GeoIpCountry fromEnv(Map<String, String> env) {
        String value = env.get(ENV_DATABASE);
        if (value == null || value.isBlank()) {
            return null;
        }
        return new GeoIpCountry(Path.of(value.trim()), System::currentTimeMillis);
    }

    GeoIpCountry(Path path, LongSupplier clock) {
        this.path = path;
        this.clock = clock;
        reload();
    }

    /** @return the ISO country code of an IP literal, or null when unknown. Never resolves host names. */
    public String country(String address) {
        if (clock.getAsLong() >= nextCheck) {
            reload();
        }
        Loaded loaded = current;
        byte[] ip = Networks.parse(address);
        if (loaded == null || ip == null) {
            return null;
        }
        try {
            return isoCode(loaded.reader().lookup(ip));
        } catch (RuntimeException e) {
            log.debugf("Adaptive risk GeoIP lookup failed: %s", e.getClass().getName());
            return null;
        }
    }

    /**
     * Reads country.iso_code, the layout of MaxMind and DB-IP country databases, or a top-level
     * country_code, the flat layout some other providers use.
     */
    static String isoCode(Object record) {
        if (!(record instanceof Map<?, ?> map)) {
            return null;
        }
        if (map.get("country") instanceof Map<?, ?> country && country.get("iso_code") instanceof String code) {
            return Countries.normalize(code);
        }
        return map.get("country_code") instanceof String code ? Countries.normalize(code) : null;
    }

    private synchronized void reload() {
        long now = clock.getAsLong();
        if (now < nextCheck) {
            return;
        }
        nextCheck = now + RELOAD_CHECK_MILLIS;
        long modified;
        try {
            modified = Files.getLastModifiedTime(path).toMillis();
        } catch (Exception e) {
            if (current == null && failedModified != -1) {
                failedModified = -1;
                log.warnf("Adaptive risk GeoIP database %s is not readable; country lookups are off until it is", path);
            }
            return;
        }
        Loaded loaded = current;
        if ((loaded != null && loaded.modified() == modified) || failedModified == modified) {
            return;
        }
        try {
            long size = Files.size(path);
            if (size > MAX_FILE_BYTES) {
                throw new MaxMindDbReader.InvalidDatabaseException("file is " + size + " bytes");
            }
            MaxMindDbReader reader = new MaxMindDbReader(Files.readAllBytes(path));
            current = new Loaded(reader, modified);
            failedModified = Long.MIN_VALUE;
            log.infof("Adaptive risk GeoIP database loaded: %s (%s, built %s)", path, reader.databaseType(),
                    reader.buildEpoch() > 0 ? Instant.ofEpochSecond(reader.buildEpoch()) : "unknown");
        } catch (Exception e) {
            failedModified = modified;
            log.warnf("Adaptive risk GeoIP database %s could not be loaded (%s: %s); %s", path,
                    e.getClass().getSimpleName(), e.getMessage(),
                    loaded == null ? "country lookups are off until it is fixed" : "still using the previous file");
        }
    }
}
