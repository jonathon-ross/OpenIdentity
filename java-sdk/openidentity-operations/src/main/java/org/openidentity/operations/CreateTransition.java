package org.openidentity.operations;

import java.util.List;
import java.util.Objects;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.IdentityStateV1;
import org.openidentity.core.IdentityStatus;
import org.openidentity.core.OpenIdentityError;
import org.openidentity.core.OpenIdentityException;
import org.openidentity.core.StateHash;
import org.openidentity.crypto.PolicyVerifier;
import org.openidentity.crypto.SignatureProof;
import org.openidentity.crypto.SigningInputs;

public final class CreateTransition {
  private CreateTransition() {}

  public static IdentityStateV1 apply(
      CreateOperation operation, List<SignatureProof> authorizationProofs) {
    Objects.requireNonNull(operation, "operation");
    Objects.requireNonNull(authorizationProofs, "authorizationProofs");

    byte[] operationBytes = operation.encode();
    byte[] signingInput = SigningInputs.operation(operationBytes);

    if (!PolicyVerifier.verify(operation.controllerPolicy(), signingInput, authorizationProofs)) {
      throw new OpenIdentityException(
          OpenIdentityError.CONTROLLER_THRESHOLD_NOT_SATISFIED,
          "CREATE authorization does not satisfy proposed ControllerPolicy");
    }

    return new IdentityStateV1(
        operation.identity(),
        operation.sequence(),
        IdentityStatus.ACTIVE,
        operation.controllerPolicy(),
        operation.recoveryCommitment());
  }

  public static StateHash resultingStateHash(
      CreateOperation operation, List<SignatureProof> proofs) {
    return StateHash.fromStateBytes(OpenIdentityCborEncoder.encodeState(apply(operation, proofs)));
  }
}
