package io.skycloak.keycloak.adaptiverisk;

import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Which request headers the operator trusts for the client address and the country, delivered as
 * environment variables. A header is only trustworthy when the operator's own proxy always sets
 * it, overwriting whatever the client sent.
 *
 * @param clientIpHeader header holding the client IP, or null to use Keycloak's resolved address
 * @param countryHeader  header holding an ISO country code, or null to skip the country reasons
 */
public record TrustedHeaders(String clientIpHeader, String countryHeader) {

    public static final String ENV_CLIENT_IP_HEADER = "SKYCLOAK_ADAPTIVE_RISK_CLIENT_IP_HEADER";
    public static final String ENV_COUNTRY_HEADER = "SKYCLOAK_ADAPTIVE_RISK_COUNTRY_HEADER";

    private static final Pattern COUNTRY = Pattern.compile("[A-Z][A-Z0-9]");
    /** Cloudflare's code for an unknown country. */
    private static final String UNKNOWN_COUNTRY = "XX";

    public static TrustedHeaders fromEnv(Map<String, String> env) {
        return new TrustedHeaders(trimmed(env.get(ENV_CLIENT_IP_HEADER)), trimmed(env.get(ENV_COUNTRY_HEADER)));
    }

    /**
     * @param header          looks up a request header by name
     * @param resolvedAddress Keycloak's resolved client address
     */
    public String clientAddress(Function<String, String> header, String resolvedAddress) {
        if (clientIpHeader != null) {
            String value = trimmed(header.apply(clientIpHeader));
            if (value != null) {
                int comma = value.indexOf(',');
                return comma >= 0 ? value.substring(0, comma).trim() : value;
            }
        }
        return resolvedAddress;
    }

    /** @return the upper-case country code, or null when unknown or not trusted. */
    public String country(Function<String, String> header) {
        if (countryHeader == null) {
            return null;
        }
        String value = trimmed(header.apply(countryHeader));
        if (value == null) {
            return null;
        }
        String code = value.toUpperCase(Locale.ROOT);
        if (!COUNTRY.matcher(code).matches() || UNKNOWN_COUNTRY.equals(code)) {
            return null;
        }
        return code;
    }

    private static String trimmed(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }
}
