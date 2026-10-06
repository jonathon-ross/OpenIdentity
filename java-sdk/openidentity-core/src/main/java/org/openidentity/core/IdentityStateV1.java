package org.openidentity.core;

import java.util.Objects;

/**
 * Version-1 authoritative identity state.
 *
 * <p>State v1 contains controller authority and an optional recovery commitment, but no assertion
 * authority. Credential issuance therefore requires an explicit transition to {@link
 * IdentityStateV2}.
 *
 * @param identity governed identity
 * @param sequence operation sequence that produced this state
 * @param status lifecycle status
 * @param controllerPolicy controller authority
 * @param recoveryCommitment recovery commitment, or {@code null}
 */
public record IdentityStateV1(
    IdentityId identity,
    Sequence sequence,
    IdentityStatus status,
    ControllerPolicy controllerPolicy,
    RecoveryCommitment recoveryCommitment)
    implements IdentityState {
  /** Validates required state fields. */
  public IdentityStateV1 {
    Objects.requireNonNull(identity, "identity");
    Objects.requireNonNull(sequence, "sequence");
    Objects.requireNonNull(status, "status");
    Objects.requireNonNull(controllerPolicy, "controllerPolicy");
  }

  @Override
  public int stateVersion() {
    return 1;
  }
}
