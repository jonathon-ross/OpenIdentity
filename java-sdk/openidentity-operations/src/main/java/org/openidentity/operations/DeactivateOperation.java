package org.openidentity.operations;

import java.math.BigInteger;
import java.util.Objects;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.IdentityId;
import org.openidentity.core.OperationType;
import org.openidentity.core.Sequence;
import org.openidentity.core.StateHash;

/**
 * Operation that changes an ACTIVE identity to DEACTIVATED.
 *
 * @param identity affected identity
 * @param sequence exact predecessor sequence plus one
 * @param previousStateHash hash of the exact predecessor state
 */
public record DeactivateOperation(
    IdentityId identity, Sequence sequence, StateHash previousStateHash)
    implements OpenIdentityOperation {
  /** Validates structural DEACTIVATE fields. */
  public DeactivateOperation {
    Objects.requireNonNull(identity);
    Objects.requireNonNull(sequence);
    Objects.requireNonNull(previousStateHash);
    if (sequence.value().compareTo(BigInteger.TWO) < 0) {
      throw new IllegalArgumentException("DEACTIVATE sequence must be >= 2");
    }
  }

  @Override
  public int protocolVersion() {
    return 1;
  }

  @Override
  public OperationType operationType() {
    return OperationType.DEACTIVATE;
  }

  @Override
  public byte[] encode() {
    return OpenIdentityCborEncoder.encodeDeactivateOperation(identity, sequence, previousStateHash);
  }
}
