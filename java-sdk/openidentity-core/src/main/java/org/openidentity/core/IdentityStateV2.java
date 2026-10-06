package org.openidentity.core;

import java.util.Objects;

/**
 * Version-2 authoritative identity state with explicit assertion authority.
 *
 * <p>A {@code null} {@code assertionPolicy} means that the identity currently has no assertion
 * authority. Controller keys do not become assertion keys by fallback.
 *
 * @param identity governed identity
 * @param sequence operation sequence that produced this state
 * @param status lifecycle status
 * @param controllerPolicy controller authority
 * @param recoveryCommitment recovery commitment, or {@code null}
 * @param assertionPolicy assertion authority, or {@code null} when disabled
 */
public record IdentityStateV2(
    IdentityId identity,
    Sequence sequence,
    IdentityStatus status,
    ControllerPolicy controllerPolicy,
    RecoveryCommitment recoveryCommitment,
    AssertionPolicy assertionPolicy)
    implements IdentityState {
  /** Validates required state fields. */
  public IdentityStateV2 {
    Objects.requireNonNull(identity, "identity");
    Objects.requireNonNull(sequence, "sequence");
    Objects.requireNonNull(status, "status");
    Objects.requireNonNull(controllerPolicy, "controllerPolicy");
  }

  @Override
  public int stateVersion() {
    return 2;
  }
}
