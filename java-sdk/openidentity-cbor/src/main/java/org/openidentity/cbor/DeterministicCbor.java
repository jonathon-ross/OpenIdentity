package org.openidentity.cbor;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/** Minimal RFC 8949 deterministic encoder for OpenIdentity's v0.1 data model. */
final class DeterministicCbor {
  private final ByteArrayOutputStream out = new ByteArrayOutputStream();

  void unsigned(BigInteger value) {
    if (value.signum() < 0 || value.bitLength() > 64)
      throw new IllegalArgumentException("CBOR uint64 required");
    typeAndArgument(0, value);
  }

  void integer(long value) {
    if (value >= 0) unsigned(BigInteger.valueOf(value));
    else typeAndArgument(1, BigInteger.valueOf(-1L - value));
  }

  void bytes(byte[] value) {
    typeAndArgument(2, BigInteger.valueOf(value.length));
    out.writeBytes(value);
  }

  void text(String value) {
    byte[] b = value.getBytes(StandardCharsets.UTF_8);
    typeAndArgument(3, BigInteger.valueOf(b.length));
    out.writeBytes(b);
  }

  void array(int size) {
    typeAndArgument(4, BigInteger.valueOf(size));
  }

  void map(int size) {
    typeAndArgument(5, BigInteger.valueOf(size));
  }

  void nil() {
    out.write(0xf6);
  }

  void bool(boolean value) {
    out.write(value ? 0xf5 : 0xf4);
  }

  void number(BigInteger value) {
    if (value.signum() >= 0) unsigned(value);
    else {
      BigInteger n = value.negate().subtract(BigInteger.ONE);
      if (n.bitLength() > 64) throw new IllegalArgumentException("CBOR integer out of range");
      typeAndArgument(1, n);
    }
  }

  byte[] toByteArray() {
    return out.toByteArray();
  }

  private void typeAndArgument(int major, BigInteger value) {
    if (value.compareTo(BigInteger.valueOf(24)) < 0) {
      out.write((major << 5) | value.intValue());
      return;
    }
    if (value.bitLength() <= 8) {
      out.write((major << 5) | 24);
      out.write(value.intValue());
      return;
    }
    if (value.bitLength() <= 16) {
      out.write((major << 5) | 25);
      writeFixed(value, 2);
      return;
    }
    if (value.bitLength() <= 32) {
      out.write((major << 5) | 26);
      writeFixed(value, 4);
      return;
    }
    if (value.bitLength() <= 64) {
      out.write((major << 5) | 27);
      writeFixed(value, 8);
      return;
    }
    throw new IllegalArgumentException("CBOR argument exceeds uint64");
  }

  private void writeFixed(BigInteger value, int bytes) {
    byte[] raw = value.toByteArray();
    for (int i = bytes - 1; i >= 0; i--)
      out.write(i < raw.length ? raw[raw.length - 1 - i] & 0xff : 0);
  }
}
