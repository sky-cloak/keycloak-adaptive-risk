package io.skycloak.keycloak.adaptiverisk.it;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/** Codes for the test users' OTP credential (HmacSHA1, 6 digits, 30 seconds). */
final class Totp {

    /** The secret in the realm file. Keycloak keys the HMAC with its bytes as stored, not base32-decoded. */
    static final String SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    private Totp() {
    }

    static String now() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA1"));
        byte[] hash = mac.doFinal(ByteBuffer.allocate(8).putLong(System.currentTimeMillis() / 30_000).array());
        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ByteBuffer.wrap(hash, offset, 4).getInt() & 0x7FFFFFFF;
        return String.format("%06d", binary % 1_000_000);
    }
}
