package io.skycloak.keycloak.adaptiverisk;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * One user's bounded login history in one realm, built only from successful logins.
 *
 * <p>Each list maps a value to the epoch milliseconds it was last seen, ordered from least to
 * most recently seen. Recording a login refreshes the entries it touches, drops entries unseen
 * for longer than the retention, and evicts the least recently seen entries beyond each cap.
 */
public class RiskProfile {

    public static final int MAX_DEVICES = 20;
    public static final int MAX_NETWORKS = 50;
    public static final int MAX_COUNTRIES = 20;

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    private int loginCount;
    private long lastLoginAt;
    private String lastCountry;
    private final LinkedHashMap<String, Long> devices = new LinkedHashMap<>();
    private final LinkedHashMap<String, Long> networks = new LinkedHashMap<>();
    private final LinkedHashMap<String, Long> countries = new LinkedHashMap<>();
    private final TreeMap<Integer, Long> hours = new TreeMap<>();

    public int loginCount() {
        return loginCount;
    }

    public long lastLoginAt() {
        return lastLoginAt;
    }

    /** Country of the last successful login, or null when it was unknown. */
    public String lastCountry() {
        return lastCountry;
    }

    public boolean knowsDevice(String deviceHash) {
        return deviceHash != null && devices.containsKey(deviceHash);
    }

    public boolean knowsNetwork(String network) {
        return network != null && networks.containsKey(network);
    }

    public boolean knowsCountry(String country) {
        return country != null && countries.containsKey(country);
    }

    public boolean hasCountries() {
        return !countries.isEmpty();
    }

    /** Whether a past successful login happened at this UTC hour or the hour on either side. */
    public boolean knowsHourNear(int hourUtc) {
        return hours.containsKey(Math.floorMod(hourUtc - 1, 24))
                || hours.containsKey(Math.floorMod(hourUtc, 24))
                || hours.containsKey(Math.floorMod(hourUtc + 1, 24));
    }

    public int deviceCount() {
        return devices.size();
    }

    public int networkCount() {
        return networks.size();
    }

    public int countryCount() {
        return countries.size();
    }

    /** Learns one successful login. */
    public void recordSuccess(LoginSignals login, Duration retention) {
        long now = login.timestamp();
        loginCount = loginCount == Integer.MAX_VALUE ? loginCount : loginCount + 1;
        lastLoginAt = Math.max(lastLoginAt, now);
        lastCountry = login.country();

        touch(devices, login.deviceHash(), now);
        touch(networks, login.network(), now);
        touch(countries, login.country(), now);
        hours.put(Math.floorMod(login.hourUtc(), 24), now);

        long cutoff = now - retention.toMillis();
        dropOlderThan(devices, cutoff);
        dropOlderThan(networks, cutoff);
        dropOlderThan(countries, cutoff);
        dropOlderThan(hours, cutoff);

        cap(devices, MAX_DEVICES);
        cap(networks, MAX_NETWORKS);
        cap(countries, MAX_COUNTRIES);
    }

    private static void touch(LinkedHashMap<String, Long> entries, String key, long now) {
        if (key == null) {
            return;
        }
        // Re-insert so iteration order stays least to most recently seen.
        entries.remove(key);
        entries.put(key, now);
    }

    private static void dropOlderThan(Map<?, Long> entries, long cutoff) {
        entries.values().removeIf(lastSeen -> lastSeen < cutoff);
    }

    private static void cap(LinkedHashMap<String, Long> entries, int max) {
        Iterator<String> oldestFirst = entries.keySet().iterator();
        while (entries.size() > max && oldestFirst.hasNext()) {
            oldestFirst.next();
            oldestFirst.remove();
        }
    }

    /** The lists as JSON, for the profile table's HISTORY column. */
    public String historyJson() {
        History history = new History();
        history.lastCountry = lastCountry;
        history.devices = devices;
        history.networks = networks;
        history.countries = countries;
        history.hours = hours;
        try {
            return MAPPER.writeValueAsString(history);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Cannot serialize risk profile", e);
        }
    }

    /** Rebuilds a stored profile. A null history gives a profile with counters but no lists. */
    public static RiskProfile restore(int loginCount, long lastLoginAt, String historyJson) {
        RiskProfile profile = new RiskProfile();
        profile.loginCount = Math.max(0, loginCount);
        profile.lastLoginAt = lastLoginAt;
        if (historyJson == null || historyJson.isBlank()) {
            return profile;
        }
        History history;
        try {
            history = MAPPER.readValue(historyJson, History.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Cannot read risk profile", e);
        }
        profile.lastCountry = history.lastCountry;
        restoreOrdered(profile.devices, history.devices);
        restoreOrdered(profile.networks, history.networks);
        restoreOrdered(profile.countries, history.countries);
        if (history.hours != null) {
            history.hours.forEach((hour, lastSeen) -> {
                if (hour != null && lastSeen != null) {
                    profile.hours.put(Math.floorMod(hour, 24), lastSeen);
                }
            });
        }
        return profile;
    }

    private static void restoreOrdered(LinkedHashMap<String, Long> target, Map<String, Long> stored) {
        if (stored == null) {
            return;
        }
        // Stored order is already oldest first, but sort anyway so a hand-edited row still evicts correctly.
        stored.entrySet().stream()
                .filter(e -> e.getKey() != null && e.getValue() != null)
                .sorted(Map.Entry.comparingByValue())
                .forEachOrdered(e -> target.put(e.getKey(), e.getValue()));
    }

    /** Serialized form of the lists. Field names are part of the stored schema. */
    static final class History {
        public String lastCountry;
        public Map<String, Long> devices;
        public Map<String, Long> networks;
        public Map<String, Long> countries;
        public Map<Integer, Long> hours;
    }
}
