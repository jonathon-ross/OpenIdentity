package org.openidentity.cbor;

import org.openidentity.core.*;

/**
 * Neutral decoded representation of an OpenIdentity operation.
 *
 * <p>This type keeps the CBOR module independent of the higher-level operations module.
 *
 * @param protocolVersion signed wire protocol version
 * @param operationType operation registry type
 * @param identity affected identity
 * @param sequence operation sequence
 * @param previousStateHash predecessor hash, or {@code null} for CREATE
 * @param controllerPolicy CREATE/proposed/new controller policy when applicable
 * @param assertionPolicy proposed assertion policy for SET_ASSERTION_POLICY
 * @param recoveryPolicy revealed current recovery policy for RECOVER
 * @param recoveryCommitment CREATE/new recovery commitment when applicable
 */
public record DecodedOperation(
    int protocolVersion,
    OperationType operationType,
    IdentityId identity,
    Sequence sequence,
    StateHash previousStateHash,
    ControllerPolicy controllerPolicy,
    AssertionPolicy assertionPolicy,
    RecoveryPolicy recoveryPolicy,
    RecoveryCommitment recoveryCommitment) {}
