package org.openidentity.cbor;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class CborReader {
  private final byte[] data;
  private int offset;

  CborReader(byte[] data) {
    this.data = data.clone();
  }

  Object read() {
    int initial = u8();
    int major = initial >>> 5;
    int ai = initial & 31;
    return switch (major) {
      case 0 -> argument(ai);
      case 1 -> argument(ai).negate().subtract(BigInteger.ONE);
      case 2 -> bytes(exactInt(argument(ai)));
      case 4 -> array(exactInt(argument(ai)));
      case 5 -> map(exactInt(argument(ai)));
      case 7 -> simple(ai);
      default -> throw new IllegalArgumentException("Unsupported CBOR major type: " + major);
    };
  }

  private Object simple(int additionalInformation) {
    if (additionalInformation == 22) return null;
    throw new IllegalArgumentException("Unsupported CBOR simple value: " + additionalInformation);
  }

  boolean exhausted() {
    return offset == data.length;
  }

  private List<Object> array(int size) {
    ArrayList<Object> values = new ArrayList<>(size);
    for (int i = 0; i < size; i++) values.add(read());
    return List.copyOf(values);
  }

  private Map<Object, Object> map(int size) {
    LinkedHashMap<Object, Object> values = new LinkedHashMap<>();
    for (int i = 0; i < size; i++) {
      Object key = read();
      if (values.containsKey(key)) {
        throw new IllegalArgumentException("Duplicate CBOR map key");
      }
      values.put(key, read());
    }
    return java.util.Collections.unmodifiableMap(values);
  }

  private byte[] bytes(int size) {
    if (size < 0 || offset + size > data.length)
      throw new IllegalArgumentException("Truncated CBOR byte string");
    byte[] value = java.util.Arrays.copyOfRange(data, offset, offset + size);
    offset += size;
    return value;
  }

  private BigInteger argument(int ai) {
    if (ai < 24) return BigInteger.valueOf(ai);
    int bytes =
        switch (ai) {
          case 24 -> 1;
          case 25 -> 2;
          case 26 -> 4;
          case 27 -> 8;
          default -> throw new IllegalArgumentException("Indefinite/reserved CBOR argument");
        };
    if (offset + bytes > data.length) throw new IllegalArgumentException("Truncated CBOR argument");
    byte[] value = new byte[bytes + 1];
    System.arraycopy(data, offset, value, 1, bytes);
    offset += bytes;
    return new BigInteger(value);
  }

  private int exactInt(BigInteger value) {
    try {
      return value.intValueExact();
    } catch (ArithmeticException e) {
      throw new IllegalArgumentException("CBOR collection too large", e);
    }
  }

  private int u8() {
    if (offset >= data.length) throw new IllegalArgumentException("Unexpected end of CBOR");
    return data[offset++] & 0xff;
  }
}
