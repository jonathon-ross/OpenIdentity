package org.openidentity.core;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Immutable 32-byte OpenIdentity root identifier.
 *
 * <p>This type represents the raw protocol identity bytes. Textual DID representation is
 * deliberately kept outside the canonical protocol model.
 */
public final class IdentityId {
  public static final int LENGTH = 32;

  private final byte[] bytes;

  private IdentityId(byte[] bytes) {
    this.bytes = bytes;
  }

  public static IdentityId of(byte[] bytes) {
    Objects.requireNonNull(bytes, "bytes");
    if (bytes.length != LENGTH) {
      throw new IllegalArgumentException(
          "OpenIdentity identity must be exactly " + LENGTH + " bytes");
    }
    return new IdentityId(bytes.clone());
  }

  public static IdentityId random(SecureRandom random) {
    Objects.requireNonNull(random, "random");
    byte[] value = new byte[LENGTH];
    random.nextBytes(value);
    return new IdentityId(value);
  }

  public byte[] bytes() {
    return bytes.clone();
  }

  public String hex() {
    return HexFormat.of().formatHex(bytes);
  }

  @Override
  public boolean equals(Object other) {
    return this == other || other instanceof IdentityId that && Arrays.equals(bytes, that.bytes);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(bytes);
  }

  @Override
  public String toString() {
    return "IdentityId[" + hex() + "]";
  }
}
