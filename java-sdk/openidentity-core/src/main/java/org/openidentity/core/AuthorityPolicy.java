package org.openidentity.core;

import java.util.List;

/**
 * Common view of an OpenIdentity cryptographic authority policy.
 *
 * <p>A policy defines the distinct verification methods authorized for one role and the number of
 * valid distinct proofs required to satisfy that authority.
 */
public interface AuthorityPolicy {
  /**
   * Returns the number of distinct authorized valid proofs required.
   *
   * @return policy threshold
   */
  int threshold();

  /**
   * Returns the immutable canonical verification-method list.
   *
   * @return authorized verification methods
   */
  List<VerificationMethod> methods();

  /**
   * Returns whether this policy has SINGLE semantics.
   *
   * @return {@code true} only for one method with threshold one
   */
  default boolean isSingle() {
    return threshold() == 1 && methods().size() == 1;
  }
}
