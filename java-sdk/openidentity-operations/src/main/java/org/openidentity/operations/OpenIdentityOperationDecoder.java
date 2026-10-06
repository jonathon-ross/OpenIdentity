package org.openidentity.operations;

import java.util.Objects;
import org.openidentity.cbor.DecodedOperation;
import org.openidentity.cbor.OpenIdentityCborDecoder;

/** Decodes canonical operation bytes into the SDK's typed immutable operation model. */
public final class OpenIdentityOperationDecoder {
  private OpenIdentityOperationDecoder() {}

  /**
   * Decodes one complete canonical OpenIdentity operation.
   *
   * <p>The decoder rejects malformed structures, unsupported protocol versions/types, trailing
   * bytes, and non-canonical encodings.
   *
   * @param operationBytes complete deterministic CBOR operation bytes
   * @return typed operation
   * @throws IllegalArgumentException if the operation is malformed, unsupported, or non-canonical
   */
  public static OpenIdentityOperation decode(byte[] operationBytes) {
    Objects.requireNonNull(operationBytes, "operationBytes");
    DecodedOperation decoded = OpenIdentityCborDecoder.decodeOperation(operationBytes);
    return switch (decoded.operationType()) {
      case CREATE ->
          new CreateOperation(
              decoded.identity(), decoded.controllerPolicy(), decoded.recoveryCommitment());
      case ROTATE_CONTROLLER ->
          new RotateControllerOperation(
              decoded.identity(),
              decoded.sequence(),
              decoded.previousStateHash(),
              decoded.controllerPolicy());
      case SET_ASSERTION_POLICY ->
          new SetAssertionPolicyOperation(
              decoded.identity(),
              decoded.sequence(),
              decoded.previousStateHash(),
              decoded.assertionPolicy());
      case DEACTIVATE ->
          new DeactivateOperation(
              decoded.identity(), decoded.sequence(), decoded.previousStateHash());
      case RECOVER ->
          new RecoverOperation(
              decoded.identity(),
              decoded.sequence(),
              decoded.previousStateHash(),
              decoded.controllerPolicy(),
              decoded.recoveryPolicy(),
              decoded.recoveryCommitment());
    };
  }
}
