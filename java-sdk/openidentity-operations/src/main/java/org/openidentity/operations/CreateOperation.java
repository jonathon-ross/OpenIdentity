package org.openidentity.operations;

import java.util.Objects;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.ControllerPolicy;
import org.openidentity.core.IdentityId;
import org.openidentity.core.OperationType;
import org.openidentity.core.RecoveryCommitment;
import org.openidentity.core.Sequence;

/**
 * CREATE operation establishing the first state of an OpenIdentity identity.
 *
 * <p>CREATE always has sequence 1 and no predecessor StateHash. Authorization is evaluated against
 * the proposed {@link ControllerPolicy}.
 *
 * @param identity new identity identifier
 * @param controllerPolicy initial controller authority
 * @param recoveryCommitment optional initial recovery commitment
 */
public record CreateOperation(
    IdentityId identity, ControllerPolicy controllerPolicy, RecoveryCommitment recoveryCommitment)
    implements OpenIdentityOperation {
  /** Validates required CREATE fields. */
  public CreateOperation {
    Objects.requireNonNull(identity, "identity");
    Objects.requireNonNull(controllerPolicy, "controllerPolicy");
  }

  @Override
  public int protocolVersion() {
    return 1;
  }

  @Override
  public OperationType operationType() {
    return OperationType.CREATE;
  }

  @Override
  public Sequence sequence() {
    return Sequence.of(1);
  }

  @Override
  public byte[] encode() {
    return OpenIdentityCborEncoder.encodeCreateOperation(
        identity, controllerPolicy, recoveryCommitment);
  }
}
