package org.openidentity.operations;

import java.math.BigInteger;
import java.util.Objects;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.AssertionPolicy;
import org.openidentity.core.IdentityId;
import org.openidentity.core.OperationType;
import org.openidentity.core.Sequence;
import org.openidentity.core.StateHash;

/**
 * Installs, replaces, or removes explicit assertion authority.
 *
 * <p>A {@code null} {@code assertionPolicy} removes assertion authority. It does not cause
 * controller authority to become assertion authority.
 *
 * @param identity affected identity
 * @param sequence exact predecessor sequence plus one
 * @param previousStateHash hash of the exact predecessor state
 * @param assertionPolicy proposed assertion authority, or {@code null} to remove it
 */
public record SetAssertionPolicyOperation(
    IdentityId identity,
    Sequence sequence,
    StateHash previousStateHash,
    AssertionPolicy assertionPolicy)
    implements OpenIdentityOperation {
  /** Validates structural SET_ASSERTION_POLICY fields. */
  public SetAssertionPolicyOperation {
    Objects.requireNonNull(identity);
    Objects.requireNonNull(sequence);
    Objects.requireNonNull(previousStateHash);
    if (sequence.value().compareTo(BigInteger.TWO) < 0) {
      throw new IllegalArgumentException("SET_ASSERTION_POLICY sequence must be >= 2");
    }
  }

  @Override
  public int protocolVersion() {
    return 1;
  }

  @Override
  public OperationType operationType() {
    return OperationType.SET_ASSERTION_POLICY;
  }

  @Override
  public byte[] encode() {
    return OpenIdentityCborEncoder.encodeSetAssertionPolicyOperation(
        identity, sequence, previousStateHash, assertionPolicy);
  }
}
