package org.openidentity.crypto;

import java.util.*;
import org.openidentity.core.*;

public final class RecoveryPolicyVerifier {
  private RecoveryPolicyVerifier() {}

  public static boolean verify(
      RecoveryPolicy policy, byte[] operationBytes, List<SignatureProof> proofs) {
    Objects.requireNonNull(policy);
    Objects.requireNonNull(operationBytes);
    Objects.requireNonNull(proofs);
    Map<VerificationMethodId, VerificationMethod> methods = new HashMap<>();
    for (VerificationMethod m : policy.methods()) methods.put(m.id(), m);
    Set<VerificationMethodId> seen = new HashSet<>();
    int valid = 0;
    for (SignatureProof p : proofs) {
      if (p == null || !seen.add(p.methodId())) return false;
      VerificationMethod m = methods.get(p.methodId());
      if (m == null) return false;
      if (SignatureVerifier.verify(
          m.key(), SigningInputs.recovery(operationBytes, m.id()), p.signature())) valid++;
    }
    return valid >= policy.threshold();
  }
}
