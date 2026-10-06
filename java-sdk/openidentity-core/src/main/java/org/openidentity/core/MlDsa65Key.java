package org.openidentity.core;

import java.util.Arrays;
import java.util.Objects;

/** Immutable raw ML-DSA-65 public key using the Protocol v0.1.1 COSE parameters. */
public final class MlDsa65Key implements CoseKey {
  /** Raw ML-DSA-65 public-key length in bytes. */
  public static final int LENGTH = 1952;

  private final byte[] bytes;

  private MlDsa65Key(byte[] bytes) {
    this.bytes = bytes;
  }

  /**
   * Creates an ML-DSA-65 public key.
   *
   * @param bytes raw 1952-byte public key
   * @return immutable key
   * @throws IllegalArgumentException if the length is not 1952 bytes
   */
  public static MlDsa65Key of(byte[] bytes) {
    Objects.requireNonNull(bytes, "bytes");
    if (bytes.length != LENGTH) {
      throw new IllegalArgumentException("ML-DSA-65 key must be exactly 1952 bytes");
    }
    return new MlDsa65Key(bytes.clone());
  }

  @Override
  public int coseKeyType() {
    return 7;
  }

  @Override
  public int coseAlgorithm() {
    return -49;
  }

  @Override
  public byte[] publicKey() {
    return bytes.clone();
  }

  @Override
  public boolean equals(Object other) {
    return this == other || other instanceof MlDsa65Key that && Arrays.equals(bytes, that.bytes);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(bytes);
  }
}
