package io.skycloak.keycloak.adaptiverisk;

import java.util.Locale;

/** Risk level of a login. The lowercase code is a contract: it appears in event details and metrics. */
public enum RiskLevel {
    LOW,
    MEDIUM,
    HIGH;

    public String code() {
        return name().toLowerCase(Locale.ROOT);
    }

    /** @return the level for a code, or null when the code is not a level. */
    public static RiskLevel fromCode(String code) {
        if (code == null) {
            return null;
        }
        for (RiskLevel level : values()) {
            if (level.code().equalsIgnoreCase(code.trim())) {
                return level;
            }
        }
        return null;
    }

    public boolean atLeast(RiskLevel other) {
        return compareTo(other) >= 0;
    }
}
