package org.openidentity.operations;

import java.math.BigInteger;
import java.util.Objects;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.*;

public record RecoverOperation(
    IdentityId identity,
    Sequence sequence,
    StateHash previousStateHash,
    ControllerPolicy newControllerPolicy,
    RecoveryPolicy currentRecoveryPolicy,
    RecoveryCommitment newRecoveryCommitment)
    implements OpenIdentityOperation {
  public RecoverOperation {
    Objects.requireNonNull(identity);
    Objects.requireNonNull(sequence);
    Objects.requireNonNull(previousStateHash);
    Objects.requireNonNull(newControllerPolicy);
    Objects.requireNonNull(currentRecoveryPolicy);
    Objects.requireNonNull(newRecoveryCommitment);
    if (sequence.value().compareTo(BigInteger.TWO) < 0)
      throw new IllegalArgumentException("RECOVER sequence must be >= 2");
  }

  public int protocolVersion() {
    return 1;
  }

  public OperationType operationType() {
    return OperationType.RECOVER;
  }

  public byte[] encode() {
    return OpenIdentityCborEncoder.encodeRecoverOperation(
        identity,
        sequence,
        previousStateHash,
        newControllerPolicy,
        currentRecoveryPolicy,
        newRecoveryCommitment);
  }
}
