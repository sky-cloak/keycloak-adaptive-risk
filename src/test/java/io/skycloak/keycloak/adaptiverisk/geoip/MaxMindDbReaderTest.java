package io.skycloak.keycloak.adaptiverisk.geoip;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.skycloak.keycloak.adaptiverisk.geoip.MmdbWriter.countryRecord;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MaxMindDbReaderTest {

    private static byte[] ip(String literal) throws Exception {
        return InetAddress.getByName(literal).getAddress();
    }

    @SuppressWarnings("unchecked")
    private static String isoCode(Object record) {
        return (String) ((Map<String, Object>) ((Map<String, Object>) record).get("country")).get("iso_code");
    }

    private static byte[] sampleIpv6Tree(int recordSize) throws Exception {
        return new MmdbWriter(6, recordSize)
                .insert("198.51.100.0/22", countryRecord("US"))
                .insert("198.51.101.0/24", countryRecord("MX"))
                .insert("203.0.113.0/24", countryRecord("CA"))
                .insert("2001:db8::/32", countryRecord("DE"))
                .build();
    }

    @ParameterizedTest
    @ValueSource(ints = {24, 28, 32})
    void findsIpv4AndIpv6NetworksInAnIpv6TreeForEveryRecordSize(int recordSize) throws Exception {
        MaxMindDbReader reader = new MaxMindDbReader(sampleIpv6Tree(recordSize));

        assertEquals("CA", isoCode(reader.lookup(ip("203.0.113.77"))));
        assertEquals("US", isoCode(reader.lookup(ip("198.51.100.1"))));
        assertEquals("US", isoCode(reader.lookup(ip("198.51.103.255"))));
        assertEquals("MX", isoCode(reader.lookup(ip("198.51.101.9"))), "the longer prefix wins");
        assertEquals("DE", isoCode(reader.lookup(ip("2001:db8:1234::1"))));
    }

    @Test
    void addressesOutsideEveryNetworkHaveNoRecord() throws Exception {
        MaxMindDbReader reader = new MaxMindDbReader(sampleIpv6Tree(24));

        assertNull(reader.lookup(ip("10.0.0.1")));
        assertNull(reader.lookup(ip("192.0.2.1")));
        assertNull(reader.lookup(ip("2001:db9::1")));
    }

    @Test
    void anIpv4TreeAnswersIpv4AndHasNoRecordForIpv6() throws Exception {
        MaxMindDbReader reader = new MaxMindDbReader(new MmdbWriter(4, 24)
                .insert("203.0.113.0/24", countryRecord("CA"))
                .build());

        assertEquals("CA", isoCode(reader.lookup(ip("203.0.113.1"))));
        assertNull(reader.lookup(ip("198.51.100.1")));
        assertNull(reader.lookup(ip("2001:db8::1")));
    }

    @Test
    void readsTheMetadata() throws Exception {
        MaxMindDbReader reader = new MaxMindDbReader(new MmdbWriter(6, 28)
                .databaseType("DBIP-Country-Lite")
                .insert("203.0.113.0/24", countryRecord("CA"))
                .build());

        assertEquals("DBIP-Country-Lite", reader.databaseType());
        assertEquals(6, reader.ipVersion());
        assertEquals(1_780_000_000L, reader.buildEpoch());
    }

    @Test
    void followsPointersToSharedStrings() throws Exception {
        MaxMindDbReader reader = new MaxMindDbReader(new MmdbWriter(6, 24).sharedStrings()
                .insert("198.51.100.0/24", countryRecord("US"))
                .insert("203.0.113.0/24", countryRecord("CA"))
                .build());

        assertEquals("US", isoCode(reader.lookup(ip("198.51.100.1"))));
        assertEquals("CA", isoCode(reader.lookup(ip("203.0.113.1"))));
    }

    @Test
    void decodesEveryValueType() throws Exception {
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("utf8", "Québec");
        record.put("double", 45.5);
        record.put("float", 1.5f);
        record.put("bytes", new byte[]{1, 2, 3});
        record.put("uint32", 4_000_000_000L);
        record.put("int32", -42);
        record.put("uint64", new BigInteger("18000000000000000000"));
        record.put("uint128", BigInteger.ONE.shiftLeft(100));
        record.put("bool", Boolean.TRUE);
        record.put("array", List.of("a", "b"));
        record.put("long string", "x".repeat(300));
        MaxMindDbReader reader = new MaxMindDbReader(new MmdbWriter(6, 24).insert("203.0.113.0/24", record).build());

        @SuppressWarnings("unchecked")
        Map<String, Object> found = (Map<String, Object>) reader.lookup(ip("203.0.113.1"));
        assertEquals("Québec", found.get("utf8"));
        assertEquals(45.5, found.get("double"));
        assertEquals(1.5f, found.get("float"));
        assertArrayEquals(new byte[]{1, 2, 3}, (byte[]) found.get("bytes"));
        assertEquals(4_000_000_000L, found.get("uint32"));
        assertEquals(-42, found.get("int32"));
        assertEquals(new BigInteger("18000000000000000000"), found.get("uint64"));
        assertEquals(BigInteger.ONE.shiftLeft(100), found.get("uint128"));
        assertEquals(Boolean.TRUE, found.get("bool"));
        assertEquals(List.of("a", "b"), found.get("array"));
        assertEquals(300, ((String) found.get("long string")).length());
    }

    @Test
    void decodesAllPointerSizesThatFitATestFile() {
        // Pointer at offset 0, its string far enough away to need the two- and three-byte forms.
        for (int target : new int[]{100, 2048 + 1000, 526336 + 1000}) {
            MmdbWriter.Encoder data = new MmdbWriter.Encoder(false);
            data.pointer(target);
            int padding = target - data.size();
            byte[] filler = new byte[padding];
            Arrays.fill(filler, (byte) 0xE0); // empty maps, never decoded
            data.raw(filler);
            data.encode("target");
            assertEquals("target", MaxMindDbReader.decodeForTest(data.bytes(), 0), "pointer to " + target);
        }
    }

    @Test
    void aFileWithoutMetadataIsRejected() {
        assertThrows(MaxMindDbReader.InvalidDatabaseException.class, () -> new MaxMindDbReader(new byte[1024]));
        assertThrows(MaxMindDbReader.InvalidDatabaseException.class, () -> new MaxMindDbReader(new byte[0]));
    }

    @Test
    void aTruncatedTreeIsRejectedNotMisread() throws Exception {
        byte[] whole = sampleIpv6Tree(24);
        int marker = indexOfMarker(whole);
        // Keep the metadata but drop the second half of the tree and the data section.
        byte[] cut = new byte[marker / 2 + (whole.length - marker)];
        System.arraycopy(whole, 0, cut, 0, marker / 2);
        System.arraycopy(whole, marker, cut, marker / 2, whole.length - marker);

        assertThrows(MaxMindDbReader.InvalidDatabaseException.class, () -> new MaxMindDbReader(cut));
    }

    @Test
    void aPointerToAPointerIsRejected() {
        MmdbWriter.Encoder data = new MmdbWriter.Encoder(false);
        data.pointer(2);
        data.pointer(0);

        assertThrows(MaxMindDbReader.InvalidDatabaseException.class, () -> MaxMindDbReader.decodeForTest(data.bytes(), 0));
    }

    @Test
    void deeplyNestedDataIsRejected() {
        MmdbWriter.Encoder data = new MmdbWriter.Encoder(false);
        for (int i = 0; i < 200; i++) {
            data.raw((byte) 0x01, (byte) (11 - 7)); // an array of one element (extended type 11)
        }
        data.encode("deep");

        assertThrows(MaxMindDbReader.InvalidDatabaseException.class, () -> MaxMindDbReader.decodeForTest(data.bytes(), 0));
    }

    @Test
    void sizesBeyondTheDataAreRejected() {
        MmdbWriter.Encoder data = new MmdbWriter.Encoder(false);
        data.raw((byte) (2 << 5 | 31), (byte) 0xFF, (byte) 0xFF, (byte) 0xFF); // a 16 MB string in 4 bytes

        assertThrows(MaxMindDbReader.InvalidDatabaseException.class, () -> MaxMindDbReader.decodeForTest(data.bytes(), 0));
    }

    private static int indexOfMarker(byte[] file) {
        byte[] marker = {(byte) 0xAB, (byte) 0xCD, (byte) 0xEF, 'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm'};
        outer:
        for (int i = file.length - marker.length; i >= 0; i--) {
            for (int j = 0; j < marker.length; j++) {
                if (file[i + j] != marker[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
