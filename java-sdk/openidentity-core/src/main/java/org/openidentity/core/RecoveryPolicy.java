package org.openidentity.core;

import java.util.List;

/**
 * Recovery authority revealed only when executing RECOVER.
 *
 * <p>Identity state stores a {@link RecoveryCommitment}, not the policy itself. During recovery the
 * revealed policy must hash to that commitment before its signatures are considered.
 *
 * @param threshold number of distinct valid recovery proofs required
 * @param methods authorized recovery verification methods
 */
public record RecoveryPolicy(int threshold, List<VerificationMethod> methods)
    implements AuthorityPolicy {
  /** RecoveryPolicy wire version used by Protocol v0.1.1. */
  public static final int VERSION = 1;

  /** Canonicalizes methods and validates the threshold. */
  public RecoveryPolicy {
    methods = Policies.canonicalMethods(methods);
    threshold = Policies.validateThreshold(threshold, methods.size());
  }

  /**
   * Creates a SINGLE recovery policy.
   *
   * @param method sole recovery method
   * @return policy requiring that method
   */
  public static RecoveryPolicy single(VerificationMethod method) {
    return new RecoveryPolicy(1, List.of(method));
  }
}
