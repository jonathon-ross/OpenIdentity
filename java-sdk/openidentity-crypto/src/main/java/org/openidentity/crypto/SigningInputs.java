package org.openidentity.crypto;

import java.util.Objects;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.VerificationMethodId;

/**
 * Constructs deterministic, domain-separated signing inputs for OpenIdentity operations.
 *
 * <p>Signatures from one domain must never be accepted in another domain.
 */
public final class SigningInputs {
  /** Signing-structure version used by Protocol v0.1.1. */
  public static final int VERSION = 1;

  private SigningInputs() {}

  /**
   * Builds the ordinary operation-authorization signing input.
   *
   * @param operationBytes canonical operation bytes
   * @return deterministic signing-structure bytes
   */
  public static byte[] operation(byte[] operationBytes) {
    Objects.requireNonNull(operationBytes, "operationBytes");
    return OpenIdentityCborEncoder.encodeOperationSigningInput(
        SigningDomain.OPERATION.value(), VERSION, operationBytes);
  }

  /**
   * Builds a new-controller proof-of-possession signing input.
   *
   * @param operationBytes canonical operation bytes
   * @param methodId proposed controller method proving possession
   * @return deterministic controller-proof signing bytes
   */
  public static byte[] controllerProof(byte[] operationBytes, VerificationMethodId methodId) {
    Objects.requireNonNull(operationBytes, "operationBytes");
    Objects.requireNonNull(methodId, "methodId");
    return OpenIdentityCborEncoder.encodeMethodSigningInput(
        SigningDomain.CONTROLLER_PROOF.value(), VERSION, operationBytes, methodId.bytes());
  }

  /**
   * Builds a recovery-authority signing input.
   *
   * @param operationBytes canonical RECOVER operation bytes
   * @param methodId recovery method producing the proof
   * @return deterministic recovery-domain signing bytes
   */
  public static byte[] recovery(byte[] operationBytes, VerificationMethodId methodId) {
    Objects.requireNonNull(operationBytes, "operationBytes");
    Objects.requireNonNull(methodId, "methodId");
    return OpenIdentityCborEncoder.encodeMethodSigningInput(
        SigningDomain.RECOVERY.value(), VERSION, operationBytes, methodId.bytes());
  }
}
