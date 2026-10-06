package org.openidentity.operations;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.*;
import org.openidentity.crypto.*;

/**
 * Applies ROTATE_CONTROLLER while preserving all non-controller state, including v2 assertion
 * authority.
 */
public final class RotateControllerTransition {
  private RotateControllerTransition() {}

  /**
   * Applies an authorized controller rotation to a v1 or v2 identity state.
   *
   * @param current exact current state
   * @param operation controller-rotation operation
   * @param authorizationProofs proofs satisfying the current ControllerPolicy
   * @param controllerProofs proof-of-possession for every proposed controller method
   * @return state of the same schema version with the proposed ControllerPolicy
   */
  public static IdentityState apply(
      IdentityState current,
      RotateControllerOperation operation,
      List<SignatureProof> authorizationProofs,
      List<SignatureProof> controllerProofs) {
    Objects.requireNonNull(current);
    Objects.requireNonNull(operation);
    Objects.requireNonNull(authorizationProofs);
    Objects.requireNonNull(controllerProofs);
    if (current.status() != IdentityStatus.ACTIVE)
      throw new OpenIdentityException(
          OpenIdentityError.IDENTITY_NOT_ACTIVE, "Current identity must be ACTIVE");
    if (!current.identity().equals(operation.identity()))
      throw new OpenIdentityException(OpenIdentityError.IDENTITY_MISMATCH, "Identity mismatch");
    if (!operation.sequence().value().equals(current.sequence().value().add(BigInteger.ONE)))
      throw new OpenIdentityException(
          OpenIdentityError.INVALID_SEQUENCE, "Sequence must equal current sequence + 1");

    StateHash actual = StateHash.fromStateBytes(OpenIdentityCborEncoder.encodeState(current));
    if (!actual.equals(operation.previousStateHash()))
      throw new OpenIdentityException(
          OpenIdentityError.INVALID_PREVIOUS_STATE_HASH, "previousStateHash mismatch");

    byte[] bytes = operation.encode();
    if (!PolicyVerifier.verify(
        current.controllerPolicy(), SigningInputs.operation(bytes), authorizationProofs))
      throw new OpenIdentityException(
          OpenIdentityError.CONTROLLER_THRESHOLD_NOT_SATISFIED,
          "Current ControllerPolicy authorization failed");

    if (!ProofOfPossessionVerifier.verifyAll(
        operation.proposedControllerPolicy(), bytes, controllerProofs))
      throw new OpenIdentityException(
          OpenIdentityError.INVALID_PROOF_OF_POSSESSION,
          "Proposed controller proof of possession failed");

    if (current instanceof IdentityStateV2 v2) {
      return new IdentityStateV2(
          current.identity(),
          operation.sequence(),
          IdentityStatus.ACTIVE,
          operation.proposedControllerPolicy(),
          current.recoveryCommitment(),
          v2.assertionPolicy());
    }

    return new IdentityStateV1(
        current.identity(),
        operation.sequence(),
        IdentityStatus.ACTIVE,
        operation.proposedControllerPolicy(),
        current.recoveryCommitment());
  }

  /**
   * Computes the StateHash of {@link #apply(IdentityState, RotateControllerOperation, List, List)}.
   */
  public static StateHash resultingStateHash(
      IdentityState current,
      RotateControllerOperation operation,
      List<SignatureProof> authorizationProofs,
      List<SignatureProof> controllerProofs) {
    return StateHash.fromStateBytes(
        OpenIdentityCborEncoder.encodeState(
            apply(current, operation, authorizationProofs, controllerProofs)));
  }
}
