package org.openidentity.core;

/**
 * Authoritative immutable OpenIdentity identity state.
 *
 * <p>{@link IdentityStateV1} contains controller and recovery authority. {@link IdentityStateV2}
 * explicitly adds assertion authority. State versions are protocol schema versions and are distinct
 * from the signed operation envelope's protocol version.
 */
public sealed interface IdentityState permits IdentityStateV1, IdentityStateV2 {
  /**
   * @return state schema version
   */
  int stateVersion();

  /**
   * @return identity governed by this state
   */
  IdentityId identity();

  /**
   * @return sequence of the operation that produced this state
   */
  Sequence sequence();

  /**
   * @return current lifecycle status
   */
  IdentityStatus status();

  /**
   * @return controller authority policy
   */
  ControllerPolicy controllerPolicy();

  /**
   * Returns the commitment to the configured recovery policy.
   *
   * @return recovery commitment, or {@code null} when recovery is not configured
   */
  RecoveryCommitment recoveryCommitment();
}
