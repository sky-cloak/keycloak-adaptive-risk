package io.skycloak.keycloak.adaptiverisk.geoip;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicLong;

import static io.skycloak.keycloak.adaptiverisk.geoip.MmdbWriter.countryRecord;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GeoIpCountryTest {

    @TempDir
    Path dir;

    private final AtomicLong clock = new AtomicLong(1_780_000_000_000L);
    /** Runs reloads inline, so tests see their effect at once. */
    private final Executor inline = Runnable::run;

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
        GeoIpCountry geoIp = new GeoIpCountry(sample(), clock::get, inline);

        assertNull(geoIp.country("10.0.0.1"));
        assertNull(geoIp.country("192.0.2.1"), "XX means unknown");
        assertNull(geoIp.country("192.0.2.200"), "ZZ means unknown");
        assertNull(geoIp.country(null));
        assertNull(geoIp.country("example.com"), "host names are never resolved");
    }

    @Test
    void readsTheFlatCountryCodeLayoutToo() throws Exception {
        GeoIpCountry geoIp = new GeoIpCountry(database("flat.mmdb", new MmdbWriter(6, 24)
                .insert("203.0.113.0/24", Map.of("country_code", "FR", "country_name", "France"))), clock::get, inline);

        assertEquals("FR", geoIp.country("203.0.113.1"));
    }

    @Test
    void readsATopLevelCountryCodeString() throws Exception {
        GeoIpCountry geoIp = new GeoIpCountry(database("ipinfo.mmdb", new MmdbWriter(6, 24)
                .insert("203.0.113.0/24", Map.of("country", "JP", "country_name", "Japan"))), clock::get, inline);

        assertEquals("JP", geoIp.country("203.0.113.1"));
    }

    @Test
    void legacyPlaceholderCodesCountAsUnknown() throws Exception {
        GeoIpCountry geoIp = new GeoIpCountry(database("legacy.mmdb", new MmdbWriter(6, 24)
                .insert("203.0.113.0/26", countryRecord("EU"))
                .insert("203.0.113.64/26", countryRecord("AP"))
                .insert("203.0.113.128/26", countryRecord("A1"))
                .insert("203.0.113.192/26", countryRecord("O1"))), clock::get, inline);

        assertNull(geoIp.country("203.0.113.1"));
        assertNull(geoIp.country("203.0.113.65"));
        assertNull(geoIp.country("203.0.113.129"));
        assertNull(geoIp.country("203.0.113.193"));
    }

    @Test
    void aSlowReloadNeverBlocksALookup() throws Exception {
        Path file = sample();
        List<Runnable> pending = new ArrayList<>();
        GeoIpCountry geoIp = new GeoIpCountry(file, clock::get, pending::add);
        Files.write(file, new MmdbWriter(6, 24).insert("203.0.113.0/24", countryRecord("MX")).build());
        Files.setLastModifiedTime(file, FileTime.fromMillis(Files.getLastModifiedTime(file).toMillis() + 5_000));
        clock.addAndGet(GeoIpCountry.RELOAD_CHECK_MILLIS);

        // The reload is queued, not run: the lookup answers from the loaded file at once.
        assertEquals("CA", geoIp.country("203.0.113.1"));
        assertEquals(1, pending.size(), "one reload queued");
        assertEquals("CA", geoIp.country("203.0.113.1"));
        assertEquals(1, pending.size(), "no second reload while one is pending");

        pending.get(0).run();
        assertEquals("MX", geoIp.country("203.0.113.1"));
    }

    @Test
    void aFileFinishedInTheSameSecondAsAFailedReadIsStillLoaded() throws Exception {
        Path file = dir.resolve("copying.mmdb");
        byte[] whole = new MmdbWriter(6, 24).insert("203.0.113.0/24", countryRecord("CA")).build();
        Files.write(file, java.util.Arrays.copyOf(whole, whole.length / 2));
        FileTime sameTick = FileTime.fromMillis(1_780_000_000_000L);
        Files.setLastModifiedTime(file, sameTick);
        GeoIpCountry geoIp = new GeoIpCountry(file, clock::get, inline);
        assertNull(geoIp.country("203.0.113.1"), "a half-copied file is refused");

        Files.write(file, whole);
        Files.setLastModifiedTime(file, sameTick);
        clock.addAndGet(GeoIpCountry.RELOAD_CHECK_MILLIS);

        assertEquals("CA", geoIp.country("203.0.113.1"));
    }

    @Test
    void theFileSizeCapFitsTwoCopiesOnAKeycloakHeap() {
        assertTrue(GeoIpCountry.MAX_FILE_BYTES <= 256L * 1024 * 1024, "the cap must fit a Keycloak heap twice over");
    }

    @Test
    void aMissingOrDamagedFileTurnsLookupsOffWithoutThrowing() throws Exception {
        Path missing = dir.resolve("absent.mmdb");
        Path damaged = dir.resolve("damaged.mmdb");
        Files.write(damaged, new byte[]{1, 2, 3});

        assertNull(new GeoIpCountry(missing, clock::get, inline).country("203.0.113.1"));
        assertNull(new GeoIpCountry(damaged, clock::get, inline).country("203.0.113.1"));
    }

    @Test
    void picksUpAReplacedFileAfterTheCheckInterval() throws Exception {
        Path file = sample();
        GeoIpCountry geoIp = new GeoIpCountry(file, clock::get, inline);
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
        GeoIpCountry geoIp = new GeoIpCountry(file, clock::get, inline);

        Files.write(file, new byte[]{9, 9, 9});
        Files.setLastModifiedTime(file, FileTime.fromMillis(Files.getLastModifiedTime(file).toMillis() + 5_000));
        clock.addAndGet(GeoIpCountry.RELOAD_CHECK_MILLIS);

        assertEquals("CA", geoIp.country("203.0.113.1"));
    }

    @Test
    void aFileThatAppearsLaterIsPickedUp() throws Exception {
        Path file = dir.resolve("later.mmdb");
        GeoIpCountry geoIp = new GeoIpCountry(file, clock::get, inline);
        assertNull(geoIp.country("203.0.113.1"));

        Files.write(file, new MmdbWriter(6, 24).insert("203.0.113.0/24", countryRecord("CA")).build());
        clock.addAndGet(GeoIpCountry.RELOAD_CHECK_MILLIS);

        assertEquals("CA", geoIp.country("203.0.113.1"));
    }
}
