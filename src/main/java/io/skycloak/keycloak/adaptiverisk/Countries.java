package io.skycloak.keycloak.adaptiverisk;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/** Country codes as the profile stores them: two upper-case characters, placeholders dropped. */
public final class Countries {

    private static final Pattern COUNTRY = Pattern.compile("[A-Z][A-Z0-9]");
    /**
     * Codes sources use for an unknown or non-country location: XX (Cloudflare and others), ZZ (ISO
     * user-assigned), and the legacy EU, AP, A1, A2 and O1 of older GeoIP databases.
     */
    private static final Set<String> UNKNOWN = Set.of("XX", "ZZ", "EU", "AP", "A1", "A2", "O1");

    private Countries() {
    }

    /** @return the upper-case code, or null when the value is blank, malformed or a placeholder. */
    public static String normalize(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String code = value.trim().toUpperCase(Locale.ROOT);
        if (!COUNTRY.matcher(code).matches() || UNKNOWN.contains(code)) {
            return null;
        }
        return code;
    }
}
