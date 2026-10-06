package io.skycloak.keycloak.adaptiverisk;

/**
 * What one login looks like, already reduced to what the profile stores: never a raw IP or a
 * raw device ID.
 *
 * @param deviceHash SHA-256 of the device cookie, or null when the browser sent none
 * @param network    the IPv4 /24 or IPv6 /48 prefix, or null when the address is unknown
 * @param country    ISO country code from the trusted header, or null when unknown
 * @param hourUtc    hour of the login, 0 to 23, UTC
 * @param timestamp  epoch milliseconds of the login
 * @param failures   Keycloak's brute force record, or null when brute force detection is off
 */
public record LoginSignals(String deviceHash, String network, String country, int hourUtc, long timestamp,
                           Failures failures) {

    public LoginSignals withDevice(String value) {
        return new LoginSignals(value, network, country, hourUtc, timestamp, failures);
    }

    public LoginSignals withNetwork(String value) {
        return new LoginSignals(deviceHash, value, country, hourUtc, timestamp, failures);
    }

    public LoginSignals withCountry(String value) {
        return new LoginSignals(deviceHash, network, value, hourUtc, timestamp, failures);
    }

    public LoginSignals withHour(int value) {
        return new LoginSignals(deviceHash, network, country, Math.floorMod(value, 24), timestamp, failures);
    }

    public LoginSignals withFailures(Failures value) {
        return new LoginSignals(deviceHash, network, country, hourUtc, timestamp, value);
    }

    /** The same login at another instant. The hour is kept, so tests can place logins on past days. */
    public LoginSignals at(long value) {
        return new LoginSignals(deviceHash, network, country, hourUtc, value, failures);
    }
}
