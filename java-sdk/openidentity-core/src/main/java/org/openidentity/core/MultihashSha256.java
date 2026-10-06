package org.openidentity.core;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

/** Immutable SHA2-256 Multihash using code {@code 0x12} and 32-byte digest length {@code 0x20}. */
public final class MultihashSha256 {
  /** Complete encoded Multihash length. */
  public static final int LENGTH = 34;

  private final byte[] bytes;

  private MultihashSha256(byte[] bytes) {
    this.bytes = bytes;
  }

  /**
   * Computes a SHA2-256 Multihash.
   *
   * @param input bytes to hash
   * @return encoded Multihash
   */
  public static MultihashSha256 digest(byte[] input) {
    Objects.requireNonNull(input, "input");
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(input);
      byte[] out = new byte[LENGTH];
      out[0] = 0x12;
      out[1] = 0x20;
      System.arraycopy(digest, 0, out, 2, digest.length);
      return new MultihashSha256(out);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is unavailable", e);
    }
  }

  /**
   * Loads and validates an already-encoded SHA2-256 Multihash.
   *
   * @param value complete 34-byte Multihash
   * @return validated immutable value
   * @throws IllegalArgumentException if code, digest length, or total length is invalid
   */
  public static MultihashSha256 of(byte[] value) {
    Objects.requireNonNull(value, "value");
    if (value.length != LENGTH || value[0] != 0x12 || value[1] != 0x20) {
      throw new IllegalArgumentException("Expected 34-byte SHA2-256 Multihash");
    }
    return new MultihashSha256(value.clone());
  }

  /**
   * @return defensive copy of complete Multihash bytes
   */
  public byte[] bytes() {
    return bytes.clone();
  }

  @Override
  public boolean equals(Object other) {
    return this == other
        || other instanceof MultihashSha256 that && Arrays.equals(bytes, that.bytes);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(bytes);
  }
}
