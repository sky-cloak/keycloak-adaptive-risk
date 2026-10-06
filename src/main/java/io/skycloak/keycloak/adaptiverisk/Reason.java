package io.skycloak.keycloak.adaptiverisk;

import java.util.Locale;

/**
 * A named reason in a risk assessment. The lowercase code is a contract: it appears in the
 * risk_reasons event detail and admins write SIEM rules against it.
 */
public enum Reason {
    /** The device cookie is missing or unknown for this user. */
    NEW_DEVICE(30),
    /** The IPv4 /24 or IPv6 /48 has never been seen for this user. */
    NEW_NETWORK(15),
    /** The country has never been seen for this user. */
    NEW_COUNTRY(30),
    /** The country differs from the last successful login, which was recent. */
    RAPID_COUNTRY_CHANGE(40),
    /** Keycloak's brute force record shows recent failed attempts. */
    RECENT_FAILURES(25),
    /** No past successful login at this UTC hour or the hour on either side. */
    UNUSUAL_HOUR(10),
    /** The profile has too few successful logins for history reasons. Carries no weight. */
    LEARNING(0),
    /** Reading the profile or scoring failed; the login failed open to low. Carries no weight. */
    EVALUATION_ERROR(0);

    private final int defaultWeight;

    Reason(int defaultWeight) {
        this.defaultWeight = defaultWeight;
    }

    public String code() {
        return name().toLowerCase(Locale.ROOT);
    }

    public int defaultWeight() {
        return defaultWeight;
    }

    /** Whether admins can weigh this reason. LEARNING and EVALUATION_ERROR are markers. */
    public boolean weighted() {
        return this != LEARNING && this != EVALUATION_ERROR;
    }
}
