package org.openidentity.core;

import java.util.Objects;

/**
 * Hash commitment to one canonical OpenIdentity identity state.
 *
 * <p>Protocol v0.1.1 uses a SHA2-256 Multihash: {@code 0x12 || 0x20 || SHA-256(StateBytes)}.
 *
 * @param multihash validated SHA2-256 Multihash
 */
public record StateHash(MultihashSha256 multihash) {
  /** Validates a StateHash wrapper. */
  public StateHash {
    Objects.requireNonNull(multihash, "multihash");
  }

  /**
   * Computes a StateHash from canonical deterministic state bytes.
   *
   * @param canonicalStateBytes complete canonical IdentityState encoding
   * @return StateHash over those bytes
   */
  public static StateHash fromStateBytes(byte[] canonicalStateBytes) {
    return new StateHash(MultihashSha256.digest(canonicalStateBytes));
  }

  /**
   * Returns the complete Multihash bytes, including code and digest-length prefixes.
   *
   * @return defensive copy of the StateHash bytes
   */
  public byte[] bytes() {
    return multihash.bytes();
  }
}
