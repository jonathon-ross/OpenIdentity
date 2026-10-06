package org.openidentity.core;

import java.util.List;

/**
 * Authority permitted to issue native OpenIdentity credentials for an identity.
 *
 * <p>Assertion authority is explicit in {@link IdentityStateV2}; it never implicitly falls back to
 * controller authority.
 *
 * @param threshold number of distinct valid assertion proofs required
 * @param methods authorized assertion verification methods
 */
public record AssertionPolicy(int threshold, List<VerificationMethod> methods)
    implements AuthorityPolicy {
  /** Canonicalizes methods and validates the threshold. */
  public AssertionPolicy {
    methods = Policies.canonicalMethods(methods);
    threshold = Policies.validateThreshold(threshold, methods.size());
  }

  /**
   * Creates a SINGLE assertion policy.
   *
   * @param method sole authorized assertion method
   * @return policy requiring that method
   */
  public static AssertionPolicy single(VerificationMethod method) {
    return new AssertionPolicy(1, List.of(method));
  }
}
