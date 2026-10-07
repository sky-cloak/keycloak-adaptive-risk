package io.skycloak.keycloak.adaptiverisk.geoip;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Writes small MaxMind DB files for tests, following the published format specification
 * (https://maxmind.github.io/MaxMind-DB/). Supports record sizes 24, 28 and 32, IPv4 and IPv6
 * trees, and the value types country databases use. With {@link #sharedStrings}, repeated
 * strings are written once and referenced by pointers, as real databases do.
 */
public final class MmdbWriter {

    private static final byte[] METADATA_MARKER = {(byte) 0xAB, (byte) 0xCD, (byte) 0xEF,
            'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm'};

    private final int ipVersion;
    private final int recordSize;
    private final Node root = new Node();
    private boolean sharedStrings;
    private String databaseType = "Test-Country";

    private static final class Node {
        final Node[] children = new Node[2];
        Map<String, Object> data;

        boolean isLeaf() {
            return data != null;
        }
    }

    public MmdbWriter(int ipVersion, int recordSize) {
        this.ipVersion = ipVersion;
        this.recordSize = recordSize;
    }

    public MmdbWriter sharedStrings() {
        this.sharedStrings = true;
        return this;
    }

    public MmdbWriter databaseType(String value) {
        this.databaseType = value;
        return this;
    }

    /** A record as country databases shape it: {"country": {"iso_code": code, "names": {...}}, ...}. */
    public static Map<String, Object> countryRecord(String isoCode) {
        Map<String, Object> names = new LinkedHashMap<>();
        names.put("en", "Country " + isoCode);
        names.put("de", "Land " + isoCode);
        Map<String, Object> country = new LinkedHashMap<>();
        country.put("geoname_id", 6251999L);
        country.put("is_in_european_union", Boolean.FALSE);
        country.put("iso_code", isoCode);
        country.put("names", names);
        Map<String, Object> continent = new LinkedHashMap<>();
        continent.put("code", "NA");
        continent.put("names", Map.of("en", "North America"));
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("continent", continent);
        record.put("country", country);
        record.put("registered_country", country);
        return record;
    }

    /** Maps a network (for example 203.0.113.0/24 or 2001:db8::/32) to a record. */
    public MmdbWriter insert(String cidr, Map<String, Object> data) throws Exception {
        String[] parts = cidr.split("/");
        byte[] address = InetAddress.getByName(parts[0]).getAddress();
        int prefix = Integer.parseInt(parts[1]);
        int offset = 0;
        if (ipVersion == 6 && address.length == 4) {
            // IPv4 networks live under ::/96 in an IPv6 tree.
            offset = 96;
        } else if (ipVersion == 4 && address.length == 16) {
            throw new IllegalArgumentException("IPv6 network in an IPv4 tree: " + cidr);
        }
        Node node = root;
        for (int depth = 0; depth < offset + prefix; depth++) {
            int bit = depth < offset ? 0 : bit(address, depth - offset);
            if (node.isLeaf()) {
                // A longer prefix inside an existing one: push the existing record down both sides.
                for (int side = 0; side < 2; side++) {
                    node.children[side] = new Node();
                    node.children[side].data = node.data;
                }
                node.data = null;
            }
            if (node.children[bit] == null) {
                node.children[bit] = new Node();
            }
            node = node.children[bit];
        }
        node.data = data;
        node.children[0] = null;
        node.children[1] = null;
        return this;
    }

    public byte[] build() {
        List<Node> internal = new ArrayList<>();
        Map<Node, Integer> numbers = new IdentityHashMap<>();
        Deque<Node> queue = new ArrayDeque<>();
        queue.add(root);
        while (!queue.isEmpty()) {
            Node node = queue.poll();
            numbers.put(node, internal.size());
            internal.add(node);
            for (Node child : node.children) {
                if (child != null && !child.isLeaf()) {
                    queue.add(child);
                }
            }
        }
        int nodeCount = internal.size();

        Encoder data = new Encoder(sharedStrings);
        Map<Map<String, Object>, Integer> dataOffsets = new IdentityHashMap<>();
        ByteArrayOutputStream tree = new ByteArrayOutputStream();
        for (Node node : internal) {
            long[] records = new long[2];
            for (int side = 0; side < 2; side++) {
                Node child = node.children[side];
                if (child == null) {
                    records[side] = nodeCount;
                } else if (child.isLeaf()) {
                    Integer offset = dataOffsets.get(child.data);
                    if (offset == null) {
                        offset = data.size();
                        data.encode(child.data);
                        dataOffsets.put(child.data, offset);
                    }
                    records[side] = (long) nodeCount + 16 + offset;
                } else {
                    records[side] = numbers.get(child);
                }
            }
            writeNode(tree, records[0], records[1]);
        }

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("binary_format_major_version", new Uint16(2));
        metadata.put("binary_format_minor_version", new Uint16(0));
        metadata.put("build_epoch", BigInteger.valueOf(1_780_000_000L));
        metadata.put("database_type", databaseType);
        metadata.put("description", Map.of("en", "Test database"));
        metadata.put("ip_version", new Uint16(ipVersion));
        metadata.put("languages", List.of("en", "de"));
        metadata.put("node_count", (long) nodeCount);
        metadata.put("record_size", new Uint16(recordSize));
        Encoder meta = new Encoder(false);
        meta.encode(metadata);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(tree.toByteArray());
        out.writeBytes(new byte[16]);
        out.writeBytes(data.bytes());
        out.writeBytes(METADATA_MARKER);
        out.writeBytes(meta.bytes());
        return out.toByteArray();
    }

    private void writeNode(ByteArrayOutputStream out, long left, long right) {
        switch (recordSize) {
            case 24 -> {
                writeBytes(out, left, 3);
                writeBytes(out, right, 3);
            }
            case 28 -> {
                writeBytes(out, left & 0xFFFFFF, 3);
                out.write((int) (((left >> 24) & 0x0F) << 4 | ((right >> 24) & 0x0F)));
                writeBytes(out, right & 0xFFFFFF, 3);
            }
            case 32 -> {
                writeBytes(out, left, 4);
                writeBytes(out, right, 4);
            }
            default -> throw new IllegalArgumentException("record size " + recordSize);
        }
    }

    private static void writeBytes(ByteArrayOutputStream out, long value, int count) {
        for (int i = count - 1; i >= 0; i--) {
            out.write((int) (value >> (8 * i)) & 0xFF);
        }
    }

    private static int bit(byte[] address, int index) {
        return (address[index / 8] >> (7 - index % 8)) & 1;
    }

    /** Forces a uint16 encoding for metadata fields the specification types as uint16. */
    public record Uint16(int value) {
    }

    /** Encodes values in the MaxMind DB data section format. */
    public static final class Encoder {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();
        private final boolean shareStrings;
        private final Map<String, Integer> strings = new HashMap<>();

        public Encoder(boolean shareStrings) {
            this.shareStrings = shareStrings;
        }

        public int size() {
            return out.size();
        }

        public byte[] bytes() {
            return out.toByteArray();
        }

        @SuppressWarnings("unchecked")
        public void encode(Object value) {
            if (value instanceof String s) {
                Integer earlier = shareStrings ? strings.get(s) : null;
                if (earlier != null) {
                    pointer(earlier);
                    return;
                }
                if (shareStrings) {
                    strings.put(s, out.size());
                }
                byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
                control(2, bytes.length);
                out.writeBytes(bytes);
            } else if (value instanceof Uint16 u) {
                unsigned(5, BigInteger.valueOf(u.value()));
            } else if (value instanceof Long l) {
                unsigned(6, BigInteger.valueOf(l));
            } else if (value instanceof BigInteger b) {
                unsigned(b.bitLength() > 64 ? 10 : 9, b);
            } else if (value instanceof Integer i) {
                control(8, 4);
                writeBytes(out, i, 4);
            } else if (value instanceof Double d) {
                control(3, 8);
                writeBytes(out, Double.doubleToLongBits(d), 8);
            } else if (value instanceof Float f) {
                control(15, 4);
                writeBytes(out, Float.floatToIntBits(f), 4);
            } else if (value instanceof Boolean b) {
                control(14, b ? 1 : 0);
            } else if (value instanceof byte[] bytes) {
                control(4, bytes.length);
                out.writeBytes(bytes);
            } else if (value instanceof Map<?, ?> map) {
                control(7, map.size());
                for (Map.Entry<String, Object> e : ((Map<String, Object>) map).entrySet()) {
                    encode(e.getKey());
                    encode(e.getValue());
                }
            } else if (value instanceof List<?> list) {
                control(11, list.size());
                list.forEach(this::encode);
            } else {
                throw new IllegalArgumentException("cannot encode " + value);
            }
        }

        /** A pointer to an offset in the data section, in the smallest of the four pointer sizes. */
        public void pointer(long target) {
            if (target < 2048) {
                out.write(0x20 | (int) (target >> 8));
                writeBytes(out, target & 0xFF, 1);
            } else if (target < 2048 + 524288) {
                long v = target - 2048;
                out.write(0x20 | 1 << 3 | (int) (v >> 16));
                writeBytes(out, v & 0xFFFF, 2);
            } else if (target < 526336 + 134217728) {
                long v = target - 526336;
                out.write(0x20 | 2 << 3 | (int) (v >> 24));
                writeBytes(out, v & 0xFFFFFF, 3);
            } else {
                out.write(0x20 | 3 << 3);
                writeBytes(out, target, 4);
            }
        }

        /** Raw bytes, for building corrupt or hand-made sections in tests. */
        public void raw(byte... bytes) {
            out.writeBytes(bytes);
        }

        private void unsigned(int type, BigInteger value) {
            byte[] bytes = value.toByteArray();
            int start = bytes.length > 1 && bytes[0] == 0 ? 1 : 0;
            int length = value.signum() == 0 ? 0 : bytes.length - start;
            control(type, length);
            out.write(bytes, start, length);
        }

        private void control(int type, int size) {
            int first = type <= 7 ? type << 5 : 0;
            if (size < 29) {
                out.write(first | size);
            } else if (size < 285) {
                out.write(first | 29);
            } else if (size < 65821) {
                out.write(first | 30);
            } else {
                out.write(first | 31);
            }
            if (type > 7) {
                out.write(type - 7);
            }
            if (size >= 65821) {
                writeBytes(out, size - 65821, 3);
            } else if (size >= 285) {
                writeBytes(out, size - 285, 2);
            } else if (size >= 29) {
                writeBytes(out, size - 29, 1);
            }
        }
    }
}
