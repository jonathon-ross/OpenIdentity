package org.openidentity.operations;

import java.math.BigInteger;
import java.util.*;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.*;
import org.openidentity.crypto.*;

public final class SetAssertionPolicyTransition {
  private SetAssertionPolicyTransition() {}

  public static IdentityStateV2 apply(
      IdentityState current,
      SetAssertionPolicyOperation op,
      List<SignatureProof> auth,
      List<SignatureProof> pop) {
    Objects.requireNonNull(current);
    Objects.requireNonNull(op);
    Objects.requireNonNull(auth);
    Objects.requireNonNull(pop);
    if (current.status() != IdentityStatus.ACTIVE)
      throw new OpenIdentityException(
          OpenIdentityError.IDENTITY_NOT_ACTIVE, "Current identity must be ACTIVE");
    if (!current.identity().equals(op.identity()))
      throw new OpenIdentityException(OpenIdentityError.IDENTITY_MISMATCH, "Identity mismatch");
    if (!op.sequence().value().equals(current.sequence().value().add(BigInteger.ONE)))
      throw new OpenIdentityException(
          OpenIdentityError.INVALID_SEQUENCE, "Sequence must equal current sequence + 1");
    StateHash actual = StateHash.fromStateBytes(OpenIdentityCborEncoder.encodeState(current));
    if (!actual.equals(op.previousStateHash()))
      throw new OpenIdentityException(
          OpenIdentityError.INVALID_PREVIOUS_STATE_HASH, "previousStateHash mismatch");
    byte[] bytes = op.encode();
    if (!PolicyVerifier.verify(current.controllerPolicy(), SigningInputs.operation(bytes), auth))
      throw new OpenIdentityException(
          OpenIdentityError.CONTROLLER_THRESHOLD_NOT_SATISFIED,
          "Current ControllerPolicy authorization failed");
    if (op.assertionPolicy() == null) {
      if (!pop.isEmpty())
        throw new OpenIdentityException(
            OpenIdentityError.INVALID_PROOF_OF_POSSESSION,
            "Assertion PoP must be absent when removing authority");
    } else if (!ProofOfPossessionVerifier.verifyAll(op.assertionPolicy(), bytes, pop))
      throw new OpenIdentityException(
          OpenIdentityError.INVALID_PROOF_OF_POSSESSION, "Assertion proof of possession failed");
    return new IdentityStateV2(
        current.identity(),
        op.sequence(),
        IdentityStatus.ACTIVE,
        current.controllerPolicy(),
        current.recoveryCommitment(),
        op.assertionPolicy());
  }
}
