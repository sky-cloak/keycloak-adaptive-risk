package io.skycloak.keycloak.adaptiverisk;

import io.skycloak.keycloak.adaptiverisk.geoip.GeoIpCountry;

import java.util.function.Function;

/**
 * Where a login's country comes from: the trusted country header when the request carries a
 * usable one, otherwise the GeoIP database's answer for the client address, otherwise unknown.
 *
 * @param geoIp the GeoIP database, or null when none is configured
 */
public record CountryResolver(TrustedHeaders headers, GeoIpCountry geoIp) {

    /**
     * @param header        looks up a request header by name
     * @param clientAddress the client address the evaluation uses
     * @return the ISO country code, or null when unknown
     */
    public String country(Function<String, String> header, String clientAddress) {
        String fromHeader = headers.country(header);
        if (fromHeader != null || geoIp == null) {
            return fromHeader;
        }
        return geoIp.country(clientAddress);
    }
}
