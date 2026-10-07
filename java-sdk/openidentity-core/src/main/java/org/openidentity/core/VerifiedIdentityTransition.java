package org.openidentity.core;

import java.util.Objects;

/**
 * Chain-neutral result of a fully verified OpenIdentity state transition.
 *
 * <p>This type does not perform protocol verification. A protocol-version-specific transition
 * verifier produces it only after validating the predecessor, operation/proofs, and exact successor
 * state.
 */
public record VerifiedIdentityTransition(
    byte[] identity,
    long predecessorSequence,
    byte[] predecessorStateHash,
    long successorSequence,
    byte[] successorStateBytes,
    byte[] successorStateHash,
    int protocolVersion,
    int stateVersion,
    int status) {

  public VerifiedIdentityTransition {
    Objects.requireNonNull(identity, "identity");
    Objects.requireNonNull(predecessorStateHash, "predecessorStateHash");
    Objects.requireNonNull(successorStateBytes, "successorStateBytes");
    Objects.requireNonNull(successorStateHash, "successorStateHash");
    identity = identity.clone();
    predecessorStateHash = predecessorStateHash.clone();
    successorStateBytes = successorStateBytes.clone();
    successorStateHash = successorStateHash.clone();
    if (identity.length != 32) throw new IllegalArgumentException("identity must be 32 bytes");
    if (predecessorStateHash.length != 34 || successorStateHash.length != 34)
      throw new IllegalArgumentException("StateHash must be a 34-byte SHA2-256 Multihash");
    if (predecessorSequence == Long.MAX_VALUE || successorSequence != predecessorSequence + 1)
      throw new IllegalArgumentException("successor sequence must be exact-next");
    if (protocolVersion < 1 || stateVersion < 1)
      throw new IllegalArgumentException("versions must be positive");
  }

  @Override
  public byte[] identity() {
    return identity.clone();
  }

  @Override
  public byte[] predecessorStateHash() {
    return predecessorStateHash.clone();
  }

  @Override
  public byte[] successorStateBytes() {
    return successorStateBytes.clone();
  }

  @Override
  public byte[] successorStateHash() {
    return successorStateHash.clone();
  }
}
