package io.skycloak.keycloak.adaptiverisk;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.regex.Pattern;

/** Reduces a client address to the network prefix the profile stores. A full IP is never stored. */
public final class Networks {

    private static final Pattern IPV4 = Pattern.compile("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})");
    private static final Pattern IPV6_LITERAL = Pattern.compile("[0-9a-fA-F:.]+");

    private Networks() {
    }

    /**
     * @return the IPv4 /24 (203.0.113.0/24) or IPv6 /48 (2001:db8:1234::/48) of an address
     *         literal, or null when the value is not an IP literal. Never resolves host names.
     */
    public static String prefix(String address) {
        if (address == null) {
            return null;
        }
        String value = address.trim();
        if (value.startsWith("[") && value.endsWith("]")) {
            value = value.substring(1, value.length() - 1);
        }
        int zone = value.indexOf('%');
        if (zone >= 0) {
            value = value.substring(0, zone);
        }
        if (value.isEmpty()) {
            return null;
        }
        if (IPV4.matcher(value).matches()) {
            return ipv4Prefix(value);
        }
        if (value.indexOf(':') < 0 || !IPV6_LITERAL.matcher(value).matches()) {
            return null;
        }
        try {
            // A literal containing ':' is parsed, never looked up.
            InetAddress parsed = InetAddress.getByName(value);
            if (parsed instanceof Inet4Address) {
                return ipv4Prefix(parsed.getHostAddress());
            }
            if (parsed instanceof Inet6Address) {
                byte[] b = parsed.getAddress();
                return String.format("%x:%x:%x::/48",
                        ((b[0] & 0xff) << 8) | (b[1] & 0xff),
                        ((b[2] & 0xff) << 8) | (b[3] & 0xff),
                        ((b[4] & 0xff) << 8) | (b[5] & 0xff));
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String ipv4Prefix(String dotted) {
        String[] parts = dotted.split("\\.");
        for (String part : parts) {
            if (Integer.parseInt(part) > 255) {
                return null;
            }
        }
        return Integer.parseInt(parts[0]) + "." + Integer.parseInt(parts[1]) + "." + Integer.parseInt(parts[2]) + ".0/24";
    }
}
