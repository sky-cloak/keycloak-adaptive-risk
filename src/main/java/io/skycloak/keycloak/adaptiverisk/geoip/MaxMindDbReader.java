package io.skycloak.keycloak.adaptiverisk.geoip;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal reader for the MaxMind DB file format (https://maxmind.github.io/MaxMind-DB/), the
 * format of the common free and commercial IP geolocation databases. It looks up the record of
 * one address and decodes it into plain Java values. Kept small and dependency free so the
 * extension stays one jar; it holds the whole file in memory and never writes to it.
 *
 * <p>Every offset read from the file is bounds checked: a damaged file raises
 * {@link InvalidDatabaseException}, never reads outside the file or loops.
 */
public final class MaxMindDbReader {

    /** Raised for any file that does not follow the format. */
    public static final class InvalidDatabaseException extends RuntimeException {
        InvalidDatabaseException(String message) {
            super(message);
        }
    }

    private static final byte[] METADATA_MARKER = {(byte) 0xAB, (byte) 0xCD, (byte) 0xEF,
            'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm'};
    /** The specification keeps the metadata in the last 128 KiB of the file. */
    private static final int METADATA_MAX_SIZE = 128 * 1024;
    private static final int DATA_SECTION_SEPARATOR = 16;
    /** Country records nest three levels deep; anything near this is a damaged file. */
    private static final int MAX_DEPTH = 32;

    private static final int TYPE_POINTER = 1;
    private static final int TYPE_STRING = 2;
    private static final int TYPE_DOUBLE = 3;
    private static final int TYPE_BYTES = 4;
    private static final int TYPE_UINT16 = 5;
    private static final int TYPE_UINT32 = 6;
    private static final int TYPE_MAP = 7;
    private static final int TYPE_INT32 = 8;
    private static final int TYPE_UINT64 = 9;
    private static final int TYPE_UINT128 = 10;
    private static final int TYPE_ARRAY = 11;
    private static final int TYPE_BOOLEAN = 14;
    private static final int TYPE_FLOAT = 15;

    private final ByteBuffer file;
    private final int nodeCount;
    private final int recordSize;
    private final int nodeBytes;
    private final int ipVersion;
    private final int dataStart;
    private final int dataEnd;
    private final int ipv4Start;
    private final String databaseType;
    private final long buildEpoch;

    public MaxMindDbReader(byte[] contents) {
        this.file = ByteBuffer.wrap(contents).asReadOnlyBuffer();
        int marker = findMetadataMarker(contents);
        int metadataStart = marker + METADATA_MARKER.length;
        Object decoded = new Decoder(metadataStart, contents.length).decode(metadataStart, 0).value;
        if (!(decoded instanceof Map<?, ?> metadata)) {
            throw new InvalidDatabaseException("metadata is not a map");
        }
        long nodes = number(metadata, "node_count");
        long size = number(metadata, "record_size");
        long version = number(metadata, "ip_version");
        if (size != 24 && size != 28 && size != 32) {
            throw new InvalidDatabaseException("unsupported record size " + size);
        }
        if (version != 4 && version != 6) {
            throw new InvalidDatabaseException("unsupported IP version " + version);
        }
        this.recordSize = (int) size;
        this.nodeBytes = recordSize * 2 / 8;
        if (nodes <= 0 || nodes > (long) marker / nodeBytes) {
            throw new InvalidDatabaseException("node count " + nodes + " does not fit the file");
        }
        this.nodeCount = (int) nodes;
        this.ipVersion = (int) version;
        long treeSize = (long) nodeCount * nodeBytes;
        if (treeSize + DATA_SECTION_SEPARATOR > marker) {
            throw new InvalidDatabaseException("search tree does not fit the file");
        }
        this.dataStart = (int) treeSize + DATA_SECTION_SEPARATOR;
        this.dataEnd = marker;
        Object type = metadata.get("database_type");
        this.databaseType = type instanceof String s ? s : "";
        Object epoch = metadata.get("build_epoch");
        this.buildEpoch = epoch instanceof Number n ? n.longValue() : 0L;
        this.ipv4Start = ipVersion == 6 ? findIpv4Start() : 0;
    }

    public String databaseType() {
        return databaseType;
    }

    public int ipVersion() {
        return ipVersion;
    }

    /** Seconds since the epoch at which the database was built, or 0 when it does not say. */
    public long buildEpoch() {
        return buildEpoch;
    }

    /**
     * @param address 4 bytes (IPv4) or 16 bytes (IPv6)
     * @return the decoded record of the network holding the address, or null when none does
     */
    public Object lookup(byte[] address) {
        if (address.length != 4 && address.length != 16) {
            throw new IllegalArgumentException("not an IP address: " + address.length + " bytes");
        }
        if (address.length == 16 && ipVersion == 4) {
            return null;
        }
        int node = address.length == 4 ? ipv4Start : 0;
        int bits = address.length * 8;
        for (int i = 0; i < bits && node < nodeCount; i++) {
            int bit = (address[i / 8] >> (7 - i % 8)) & 1;
            node = record(node, bit);
        }
        if (node == nodeCount) {
            return null;
        }
        if (node < nodeCount) {
            // Ran out of address bits inside the tree: the file is inconsistent.
            throw new InvalidDatabaseException("search tree is deeper than the address");
        }
        long offset = (long) node - nodeCount - DATA_SECTION_SEPARATOR;
        if (offset < 0 || offset >= dataEnd - dataStart) {
            throw new InvalidDatabaseException("record points outside the data section");
        }
        Decoder decoder = new Decoder(dataStart, dataEnd);
        return decoder.decode(dataStart + (int) offset, 0).value;
    }

    /** IPv4 addresses live under ::/96 in an IPv6 tree. */
    private int findIpv4Start() {
        int node = 0;
        for (int i = 0; i < 96 && node < nodeCount; i++) {
            node = record(node, 0);
        }
        return node;
    }

    private int record(int node, int side) {
        int base = node * nodeBytes;
        long value = switch (recordSize) {
            case 24 -> side == 0 ? uint(base, 3) : uint(base + 3, 3);
            case 28 -> side == 0
                    ? ((long) (file.get(base + 3) & 0xF0) << 20) | uint(base, 3)
                    : ((long) (file.get(base + 3) & 0x0F) << 24) | uint(base + 4, 3);
            default -> side == 0 ? uint(base, 4) : uint(base + 4, 4);
        };
        if (value > Integer.MAX_VALUE) {
            throw new InvalidDatabaseException("record value out of range");
        }
        return (int) value;
    }

    private long uint(int position, int count) {
        long value = 0;
        for (int i = 0; i < count; i++) {
            value = (value << 8) | (file.get(position + i) & 0xFF);
        }
        return value;
    }

    private static int findMetadataMarker(byte[] contents) {
        int stop = Math.max(0, contents.length - METADATA_MAX_SIZE);
        outer:
        for (int i = contents.length - METADATA_MARKER.length; i >= stop; i--) {
            for (int j = 0; j < METADATA_MARKER.length; j++) {
                if (contents[i + j] != METADATA_MARKER[j]) {
                    continue outer;
                }
            }
            return i;
        }
        throw new InvalidDatabaseException("no MaxMind DB metadata found");
    }

    private static long number(Map<?, ?> metadata, String key) {
        if (!(metadata.get(key) instanceof Number n)) {
            throw new InvalidDatabaseException("metadata has no " + key);
        }
        return n.longValue();
    }

    /** Decodes data section bytes that start at offset 0, for tests of the value encoding. */
    static Object decodeForTest(byte[] data, int offset) {
        MaxMindDbReader reader = new MaxMindDbReader(ByteBuffer.wrap(data).asReadOnlyBuffer());
        return reader.new Decoder(0, data.length).decode(offset, 0).value;
    }

    private MaxMindDbReader(ByteBuffer data) {
        this.file = data;
        this.nodeCount = 0;
        this.recordSize = 24;
        this.nodeBytes = 6;
        this.ipVersion = 6;
        this.dataStart = 0;
        this.dataEnd = data.limit();
        this.ipv4Start = 0;
        this.databaseType = "";
        this.buildEpoch = 0;
    }

    private record Decoded(Object value, int next) {
    }

    /** Decodes values between base (where pointers count from) and end. */
    private final class Decoder {
        private final int base;
        private final int end;

        Decoder(int base, int end) {
            this.base = base;
            this.end = end;
        }

        Decoded decode(int position, int depth) {
            if (depth > MAX_DEPTH) {
                throw new InvalidDatabaseException("data nested too deeply");
            }
            int control = byteAt(position++);
            int type = control >>> 5;
            if (type == TYPE_POINTER) {
                int[] pointer = pointer(control, position);
                int target = base + pointer[0];
                if (target < base || target >= end) {
                    throw new InvalidDatabaseException("pointer outside the data");
                }
                if ((byteAt(target) >>> 5) == TYPE_POINTER) {
                    throw new InvalidDatabaseException("pointer to a pointer");
                }
                return new Decoded(decode(target, depth + 1).value, pointer[1]);
            }
            if (type == 0) {
                type = 7 + byteAt(position++);
                if (type <= 7) {
                    throw new InvalidDatabaseException("invalid extended type");
                }
            }
            int size = control & 0x1F;
            if (size >= 29) {
                int extra = size - 28;
                long value = 0;
                for (int i = 0; i < extra; i++) {
                    value = (value << 8) | byteAt(position++);
                }
                size = (int) (switch (extra) {
                    case 1 -> 29 + value;
                    case 2 -> 285 + value;
                    default -> 65821 + value;
                });
            }
            return switch (type) {
                case TYPE_STRING -> {
                    check(position, size);
                    yield new Decoded(new String(bytes(position, size), StandardCharsets.UTF_8), position + size);
                }
                case TYPE_BYTES -> {
                    check(position, size);
                    yield new Decoded(bytes(position, size), position + size);
                }
                case TYPE_DOUBLE -> {
                    expectSize(type, size, 8);
                    check(position, 8);
                    yield new Decoded(Double.longBitsToDouble(unsigned(position, 8).longValue()), position + 8);
                }
                case TYPE_FLOAT -> {
                    expectSize(type, size, 4);
                    check(position, 4);
                    yield new Decoded(Float.intBitsToFloat(unsigned(position, 4).intValue()), position + 4);
                }
                case TYPE_UINT16, TYPE_UINT32 -> {
                    maxSize(type, size, type == TYPE_UINT16 ? 2 : 4);
                    check(position, size);
                    yield new Decoded(unsigned(position, size).longValue(), position + size);
                }
                case TYPE_INT32 -> {
                    maxSize(type, size, 4);
                    check(position, size);
                    int value = 0;
                    for (int i = 0; i < size; i++) {
                        value = (value << 8) | byteAt(position + i);
                    }
                    yield new Decoded(value, position + size);
                }
                case TYPE_UINT64, TYPE_UINT128 -> {
                    maxSize(type, size, type == TYPE_UINT64 ? 8 : 16);
                    check(position, size);
                    yield new Decoded(unsigned(position, size), position + size);
                }
                case TYPE_BOOLEAN -> {
                    maxSize(type, size, 1);
                    yield new Decoded(size == 1, position);
                }
                case TYPE_MAP -> {
                    // Every pair takes at least two bytes, so a size beyond that is a damaged file.
                    check(position, size * 2L);
                    Map<String, Object> map = new HashMap<>(Math.max(4, size * 2));
                    for (int i = 0; i < size; i++) {
                        Decoded key = decode(position, depth + 1);
                        if (!(key.value instanceof String k)) {
                            throw new InvalidDatabaseException("map key is not a string");
                        }
                        Decoded value = decode(key.next, depth + 1);
                        map.put(k, value.value);
                        position = value.next;
                    }
                    yield new Decoded(map, position);
                }
                case TYPE_ARRAY -> {
                    check(position, size);
                    List<Object> list = new ArrayList<>(Math.min(size, 64));
                    for (int i = 0; i < size; i++) {
                        Decoded value = decode(position, depth + 1);
                        list.add(value.value);
                        position = value.next;
                    }
                    yield new Decoded(list, position);
                }
                default -> throw new InvalidDatabaseException("unsupported data type " + type);
            };
        }

        /** @return the pointer's offset from base, and the position after it */
        private int[] pointer(int control, int position) {
            int sizeBits = (control >>> 3) & 0x3;
            int value = control & 0x7;
            int extra = sizeBits + 1;
            check(position, extra);
            long offset = switch (sizeBits) {
                case 0 -> ((long) value << 8) | uint(position, 1);
                case 1 -> (((long) value << 16) | uint(position, 2)) + 2048;
                case 2 -> (((long) value << 24) | uint(position, 3)) + 526336;
                default -> uint(position, 4);
            };
            if (offset > Integer.MAX_VALUE) {
                throw new InvalidDatabaseException("pointer out of range");
            }
            return new int[]{(int) offset, position + extra};
        }

        private int byteAt(int position) {
            if (position < 0 || position >= end) {
                throw new InvalidDatabaseException("read past the end of the data");
            }
            return file.get(position) & 0xFF;
        }

        private void check(int position, long length) {
            if (position < 0 || position + length > end) {
                throw new InvalidDatabaseException("value runs past the end of the data");
            }
        }

        private byte[] bytes(int position, int size) {
            byte[] out = new byte[size];
            file.get(position, out);
            return out;
        }

        private BigInteger unsigned(int position, int size) {
            return new BigInteger(1, bytes(position, size));
        }

        private void expectSize(int type, int size, int expected) {
            if (size != expected) {
                throw new InvalidDatabaseException("type " + type + " needs size " + expected + ", not " + size);
            }
        }

        private void maxSize(int type, int size, int max) {
            if (size > max) {
                throw new InvalidDatabaseException("type " + type + " allows at most " + max + " bytes, not " + size);
            }
        }
    }
}
