package org.openidentity.operations;

import org.openidentity.core.IdentityId;
import org.openidentity.core.OperationType;
import org.openidentity.core.Sequence;

/** Common immutable view of a canonical OpenIdentity Protocol v0.1.1 operation. */
public sealed interface OpenIdentityOperation
    permits CreateOperation,
        RotateControllerOperation,
        SetAssertionPolicyOperation,
        DeactivateOperation,
        RecoverOperation {
  /**
   * @return signed operation-envelope protocol version
   */
  int protocolVersion();

  /**
   * @return operation registry type
   */
  OperationType operationType();

  /**
   * @return identity affected by the operation
   */
  IdentityId identity();

  /**
   * @return operation sequence
   */
  Sequence sequence();

  /**
   * Returns the complete deterministic operation bytes that are bound into signing structures.
   *
   * @return canonical RFC 8949 CBOR operation bytes
   */
  byte[] encode();
}
