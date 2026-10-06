package org.openidentity.core;

import java.util.Objects;

/**
 * SHA2-256 Multihash commitment to the canonical encoding of a {@link RecoveryPolicy}.
 *
 * @param multihash committed recovery-policy digest
 */
public record RecoveryCommitment(MultihashSha256 multihash) {
  /** Validates the commitment. */
  public RecoveryCommitment {
    Objects.requireNonNull(multihash, "multihash");
  }

  /**
   * Returns complete Multihash bytes.
   *
   * @return defensive copy of commitment bytes
   */
  public byte[] bytes() {
    return multihash.bytes();
  }
}
