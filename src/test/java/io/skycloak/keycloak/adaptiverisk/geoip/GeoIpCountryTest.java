package io.skycloak.keycloak.adaptiverisk.geoip;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static io.skycloak.keycloak.adaptiverisk.geoip.MmdbWriter.countryRecord;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class GeoIpCountryTest {

    @TempDir
    Path dir;

    private final AtomicLong clock = new AtomicLong(1_780_000_000_000L);

    private Path database(String name, MmdbWriter writer) throws Exception {
        Path file = dir.resolve(name);
        Files.write(file, writer.build());
        return file;
    }

    private Path sample() throws Exception {
        return database("country.mmdb", new MmdbWriter(6, 24)
                .insert("203.0.113.0/24", countryRecord("CA"))
                .insert("198.51.100.0/24", countryRecord("us"))
                .insert("192.0.2.0/25", countryRecord("XX"))
                .insert("192.0.2.128/25", countryRecord("ZZ"))
                .insert("2001:db8::/32", countryRecord("DE")));
    }

    @Test
    void isOffWhenTheEnvVarIsUnsetOrBlank() {
        assertNull(GeoIpCountry.fromEnv(Map.of()));
        assertNull(GeoIpCountry.fromEnv(Map.of("SKYCLOAK_ADAPTIVE_RISK_GEOIP_DATABASE", "  ")));
    }

    @Test
    void looksUpTheCountryOfAnAddressLiteral() throws Exception {
        GeoIpCountry geoIp = GeoIpCountry.fromEnv(Map.of("SKYCLOAK_ADAPTIVE_RISK_GEOIP_DATABASE", sample().toString()));

        assertEquals("CA", geoIp.country("203.0.113.9"));
        assertEquals("CA", geoIp.country(" ::ffff:203.0.113.9 "));
        assertEquals("US", geoIp.country("198.51.100.1"), "codes are upper-cased");
        assertEquals("DE", geoIp.country("[2001:db8::1]"));
    }

    @Test
    void unknownAddressesAndPlaceholderCodesGiveNoCountry() throws Exception {
        GeoIpCountry geoIp = new GeoIpCountry(sample(), clock::get);

        assertNull(geoIp.country("10.0.0.1"));
        assertNull(geoIp.country("192.0.2.1"), "XX means unknown");
        assertNull(geoIp.country("192.0.2.200"), "ZZ means unknown");
        assertNull(geoIp.country(null));
        assertNull(geoIp.country("example.com"), "host names are never resolved");
    }

    @Test
    void readsTheFlatCountryCodeLayoutToo() throws Exception {
        GeoIpCountry geoIp = new GeoIpCountry(database("flat.mmdb", new MmdbWriter(6, 24)
                .insert("203.0.113.0/24", Map.of("country_code", "FR", "country", "France"))), clock::get);

        assertEquals("FR", geoIp.country("203.0.113.1"));
    }

    @Test
    void aMissingOrDamagedFileTurnsLookupsOffWithoutThrowing() throws Exception {
        Path missing = dir.resolve("absent.mmdb");
        Path damaged = dir.resolve("damaged.mmdb");
        Files.write(damaged, new byte[]{1, 2, 3});

        assertNull(new GeoIpCountry(missing, clock::get).country("203.0.113.1"));
        assertNull(new GeoIpCountry(damaged, clock::get).country("203.0.113.1"));
    }

    @Test
    void picksUpAReplacedFileAfterTheCheckInterval() throws Exception {
        Path file = sample();
        GeoIpCountry geoIp = new GeoIpCountry(file, clock::get);
        assertEquals("CA", geoIp.country("203.0.113.1"));

        Files.write(file, new MmdbWriter(6, 24).insert("203.0.113.0/24", countryRecord("MX")).build());
        Files.setLastModifiedTime(file, FileTime.fromMillis(Files.getLastModifiedTime(file).toMillis() + 5_000));
        assertEquals("CA", geoIp.country("203.0.113.1"), "not before the check interval");

        clock.addAndGet(GeoIpCountry.RELOAD_CHECK_MILLIS);
        assertEquals("MX", geoIp.country("203.0.113.1"));
    }

    @Test
    void aDamagedReplacementKeepsThePreviousDatabase() throws Exception {
        Path file = sample();
        GeoIpCountry geoIp = new GeoIpCountry(file, clock::get);

        Files.write(file, new byte[]{9, 9, 9});
        Files.setLastModifiedTime(file, FileTime.fromMillis(Files.getLastModifiedTime(file).toMillis() + 5_000));
        clock.addAndGet(GeoIpCountry.RELOAD_CHECK_MILLIS);

        assertEquals("CA", geoIp.country("203.0.113.1"));
    }

    @Test
    void aFileThatAppearsLaterIsPickedUp() throws Exception {
        Path file = dir.resolve("later.mmdb");
        GeoIpCountry geoIp = new GeoIpCountry(file, clock::get);
        assertNull(geoIp.country("203.0.113.1"));

        Files.write(file, new MmdbWriter(6, 24).insert("203.0.113.0/24", countryRecord("CA")).build());
        clock.addAndGet(GeoIpCountry.RELOAD_CHECK_MILLIS);

        assertEquals("CA", geoIp.country("203.0.113.1"));
    }
}
