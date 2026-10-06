package org.openidentity.core;

import java.util.List;

/**
 * Authority permitted to authorize ordinary OpenIdentity state transitions.
 *
 * @param threshold number of distinct valid controller proofs required
 * @param methods authorized controller verification methods
 */
public record ControllerPolicy(int threshold, List<VerificationMethod> methods)
    implements AuthorityPolicy {
  /** Canonicalizes methods and validates the threshold. */
  public ControllerPolicy {
    methods = Policies.canonicalMethods(methods);
    threshold = Policies.validateThreshold(threshold, methods.size());
  }

  /**
   * Creates a SINGLE controller policy.
   *
   * @param method sole authorized controller method
   * @return policy requiring that method
   */
  public static ControllerPolicy single(VerificationMethod method) {
    return new ControllerPolicy(1, List.of(method));
  }
}
