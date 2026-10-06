package org.openidentity.core;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/** Immutable 16-byte OpenIdentity Verification Method ID. */
public final class VerificationMethodId implements Comparable<VerificationMethodId> {
  public static final int LENGTH = 16;

  private final byte[] bytes;

  private VerificationMethodId(byte[] bytes) {
    this.bytes = bytes;
  }

  public static VerificationMethodId of(byte[] bytes) {
    Objects.requireNonNull(bytes, "bytes");
    if (bytes.length != LENGTH) {
      throw new IllegalArgumentException(
          "Verification Method ID must be exactly " + LENGTH + " bytes");
    }
    return new VerificationMethodId(bytes.clone());
  }

  public byte[] bytes() {
    return bytes.clone();
  }

  public String hex() {
    return HexFormat.of().formatHex(bytes);
  }

  @Override
  public int compareTo(VerificationMethodId other) {
    Objects.requireNonNull(other, "other");
    return Arrays.compareUnsigned(bytes, other.bytes);
  }

  @Override
  public boolean equals(Object other) {
    return this == other
        || other instanceof VerificationMethodId that && Arrays.equals(bytes, that.bytes);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(bytes);
  }

  @Override
  public String toString() {
    return "VerificationMethodId[" + hex() + "]";
  }
}
