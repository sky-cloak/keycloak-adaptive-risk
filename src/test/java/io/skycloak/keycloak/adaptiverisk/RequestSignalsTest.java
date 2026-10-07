package io.skycloak.keycloak.adaptiverisk;

import io.skycloak.keycloak.adaptiverisk.geoip.GeoIpCountry;
import io.skycloak.keycloak.adaptiverisk.geoip.MmdbWriter;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RequestSignalsTest {

    // --- network prefixes ---

    @Test
    void ipv4IsReducedToItsSlash24() {
        assertEquals("203.0.113.0/24", Networks.prefix("203.0.113.77"));
        assertEquals("203.0.113.0/24", Networks.prefix(" 203.0.113.1 "));
    }

    @Test
    void ipv6IsReducedToItsSlash48() {
        assertEquals("2001:db8:1234::/48", Networks.prefix("2001:db8:1234:5678::1"));
        assertEquals("2001:db8:1234::/48", Networks.prefix("[2001:DB8:1234:ffff:0:0:0:2]"));
        assertEquals("2001:db8:1234::/48", Networks.prefix("2001:db8:1234::9%eth0"));
    }

    @Test
    void ipv4MappedIpv6IsTreatedAsIpv4() {
        assertEquals("203.0.113.0/24", Networks.prefix("::ffff:203.0.113.9"));
    }

    @Test
    void anythingElseHasNoPrefix() {
        assertNull(Networks.prefix(null));
        assertNull(Networks.prefix(""));
        assertNull(Networks.prefix("unknown"));
        assertNull(Networks.prefix("example.com"));
        assertNull(Networks.prefix("999.1.1.1"));
        assertNull(Networks.prefix("1.2.3"));
        assertNull(Networks.prefix("gggg::1"));
    }

    // --- trusted headers ---

    @Test
    void headersAreReadFromTheTwoEnvVars() {
        TrustedHeaders headers = TrustedHeaders.fromEnv(Map.of(
                "SKYCLOAK_ADAPTIVE_RISK_CLIENT_IP_HEADER", " CF-Connecting-IP ",
                "SKYCLOAK_ADAPTIVE_RISK_COUNTRY_HEADER", "CF-IPCountry"));

        assertEquals("CF-Connecting-IP", headers.clientIpHeader());
        assertEquals("CF-IPCountry", headers.countryHeader());
    }

    @Test
    void clientAddressComesFromTheNamedHeaderWhenPresent() {
        TrustedHeaders headers = TrustedHeaders.fromEnv(Map.of("SKYCLOAK_ADAPTIVE_RISK_CLIENT_IP_HEADER", "CF-Connecting-IP"));
        Map<String, String> request = Map.of("CF-Connecting-IP", "198.51.100.4");

        assertEquals("198.51.100.4", headers.clientAddress(request::get, "10.0.0.8"));
    }

    @Test
    void clientAddressFallsBackToKeycloaksAddress() {
        TrustedHeaders named = TrustedHeaders.fromEnv(Map.of("SKYCLOAK_ADAPTIVE_RISK_CLIENT_IP_HEADER", "CF-Connecting-IP"));
        TrustedHeaders unset = TrustedHeaders.fromEnv(Map.of());
        Map<String, String> spoofing = Map.of("X-Forwarded-For", "1.1.1.1");

        assertEquals("10.0.0.8", named.clientAddress(Map.<String, String>of()::get, "10.0.0.8"));
        assertEquals("10.0.0.8", named.clientAddress(Map.of("CF-Connecting-IP", " ")::get, "10.0.0.8"));
        assertEquals("10.0.0.8", unset.clientAddress(spoofing::get, "10.0.0.8"));
    }

    @Test
    void aListInTheClientIpHeaderUsesItsFirstEntry() {
        TrustedHeaders headers = TrustedHeaders.fromEnv(Map.of("SKYCLOAK_ADAPTIVE_RISK_CLIENT_IP_HEADER", "X-Real-IP"));

        assertEquals("198.51.100.4", headers.clientAddress(Map.of("X-Real-IP", "198.51.100.4, 10.0.0.1")::get, "10.0.0.8"));
    }

    @Test
    void countryComesOnlyFromTheNamedHeader() {
        TrustedHeaders named = TrustedHeaders.fromEnv(Map.of("SKYCLOAK_ADAPTIVE_RISK_COUNTRY_HEADER", "CF-IPCountry"));
        TrustedHeaders unset = TrustedHeaders.fromEnv(Map.of("SKYCLOAK_ADAPTIVE_RISK_COUNTRY_HEADER", " "));

        assertEquals("CA", named.country(Map.of("CF-IPCountry", "ca")::get));
        assertNull(named.country(Map.<String, String>of()::get));
        assertNull(unset.country(Map.of("CF-IPCountry", "CA")::get));
    }

    @Test
    void countryMustLookLikeACountryCode() {
        TrustedHeaders headers = TrustedHeaders.fromEnv(Map.of("SKYCLOAK_ADAPTIVE_RISK_COUNTRY_HEADER", "CF-IPCountry"));

        // Cloudflare sends XX when it does not know the country.
        assertNull(headers.country(Map.of("CF-IPCountry", "XX")::get));
        assertNull(headers.country(Map.of("CF-IPCountry", "Canada")::get));
        assertNull(headers.country(Map.of("CF-IPCountry", "C;")::get));
        assertEquals("T1", headers.country(Map.of("CF-IPCountry", "T1")::get));
    }

    // --- device cookie ---

    @Test
    void newDeviceIdsAreRandomAndValid() {
        String a = DeviceCookie.newId();
        String b = DeviceCookie.newId();

        assertNotEquals(a, b);
        assertTrue(DeviceCookie.isValid(a));
        assertEquals(43, a.length());
    }

    @Test
    void malformedCookieValuesAreRejected() {
        assertFalse(DeviceCookie.isValid(null));
        assertFalse(DeviceCookie.isValid(""));
        assertFalse(DeviceCookie.isValid("short"));
        assertFalse(DeviceCookie.isValid("a".repeat(42) + ";"));
        assertFalse(DeviceCookie.isValid("a".repeat(200)));
    }

    @Test
    void deviceIdsAreStoredAsSha256Hex() {
        // Known answer: SHA-256("abc").
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", DeviceCookie.hash("abc"));
    }

    // --- country resolution ---

    @Test
    void theCountryHeaderWinsOverTheGeoIpDatabase() throws Exception {
        CountryResolver resolver = resolverWithDatabase();

        assertEquals("FR", resolver.country(Map.of("CF-IPCountry", "FR")::get, "203.0.113.9"));
    }

    @Test
    void theGeoIpDatabaseAnswersWhenTheHeaderIsAbsentOrUnknown() throws Exception {
        CountryResolver resolver = resolverWithDatabase();

        assertEquals("CA", resolver.country(Map.<String, String>of()::get, "203.0.113.9"));
        assertEquals("CA", resolver.country(Map.of("CF-IPCountry", "XX")::get, "203.0.113.9"));
    }

    @Test
    void withoutHeaderOrDatabaseThereIsNoCountry() {
        CountryResolver resolver = new CountryResolver(TrustedHeaders.fromEnv(Map.of()), null);

        assertNull(resolver.country(Map.of("CF-IPCountry", "FR")::get, "203.0.113.9"));
    }

    /** Country header CF-IPCountry, and a GeoIP database placing 203.0.113.0/24 in CA. */
    private static CountryResolver resolverWithDatabase() throws Exception {
        Path file = Files.createTempFile("country", ".mmdb");
        file.toFile().deleteOnExit();
        Files.write(file, new MmdbWriter(6, 24).insert("203.0.113.0/24", MmdbWriter.countryRecord("CA")).build());
        return new CountryResolver(TrustedHeaders.fromEnv(Map.of("SKYCLOAK_ADAPTIVE_RISK_COUNTRY_HEADER", "CF-IPCountry")),
                GeoIpCountry.fromEnv(Map.of("SKYCLOAK_ADAPTIVE_RISK_GEOIP_DATABASE", file.toString())));
    }
}
