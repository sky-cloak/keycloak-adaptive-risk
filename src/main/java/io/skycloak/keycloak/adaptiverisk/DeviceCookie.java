package io.skycloak.keycloak.adaptiverisk;

import jakarta.ws.rs.core.NewCookie;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.regex.Pattern;

/**
 * The device cookie: a random ID the browser keeps for a year. Only its SHA-256 hash is stored in
 * the profile, so the table alone cannot be used to forge a known device.
 */
public final class DeviceCookie {

    public static final String NAME = "SKYCLOAK_ADAPTIVE_RISK_DEVICE";
    static final int MAX_AGE_SECONDS = 365 * 24 * 60 * 60;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern VALID = Pattern.compile("[A-Za-z0-9_-]{43}");

    private DeviceCookie() {
    }

    /** 256 random bits, base64url without padding (43 characters). */
    public static String newId() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static boolean isValid(String value) {
        return value != null && VALID.matcher(value).matches();
    }

    public static String hash(String deviceId) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(deviceId.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    /** HttpOnly, Secure on HTTPS, scoped to the realm path, one year. */
    public static NewCookie build(String deviceId, String realmPath, boolean secure) {
        return new NewCookie.Builder(NAME)
                .value(deviceId)
                .path(realmPath)
                .maxAge(MAX_AGE_SECONDS)
                .httpOnly(true)
                .secure(secure)
                .sameSite(NewCookie.SameSite.LAX)
                .build();
    }
}
