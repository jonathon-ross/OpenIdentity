package org.openidentity.operations;

import java.util.Objects;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.*;

public record RotateControllerOperation(
    IdentityId identity,
    Sequence sequence,
    StateHash previousStateHash,
    ControllerPolicy proposedControllerPolicy)
    implements OpenIdentityOperation {
  public RotateControllerOperation {
    Objects.requireNonNull(identity, "identity");
    Objects.requireNonNull(sequence, "sequence");
    Objects.requireNonNull(previousStateHash, "previousStateHash");
    Objects.requireNonNull(proposedControllerPolicy, "proposedControllerPolicy");
    if (sequence.value().compareTo(java.math.BigInteger.TWO) < 0)
      throw new IllegalArgumentException("ROTATE_CONTROLLER sequence must be >= 2");
  }

  public int protocolVersion() {
    return 1;
  }

  public OperationType operationType() {
    return OperationType.ROTATE_CONTROLLER;
  }

  public byte[] encode() {
    return OpenIdentityCborEncoder.encodeRotateControllerOperation(
        identity, sequence, previousStateHash, proposedControllerPolicy);
  }
}
