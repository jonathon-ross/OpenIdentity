package org.openidentity.crypto;

import java.util.*;
import org.openidentity.core.*;

public final class ProofOfPossessionVerifier {
  private ProofOfPossessionVerifier() {}

  public static boolean verifyAll(
      AuthorityPolicy proposedPolicy, byte[] operationBytes, List<SignatureProof> proofs) {
    Objects.requireNonNull(proposedPolicy);
    Objects.requireNonNull(operationBytes);
    Objects.requireNonNull(proofs);
    if (proofs.size() != proposedPolicy.methods().size()) return false;
    Map<VerificationMethodId, VerificationMethod> methods = new HashMap<>();
    for (VerificationMethod m : proposedPolicy.methods()) methods.put(m.id(), m);
    Set<VerificationMethodId> seen = new HashSet<>();
    for (SignatureProof p : proofs) {
      if (p == null || !seen.add(p.methodId())) return false;
      VerificationMethod m = methods.get(p.methodId());
      if (m == null) return false;
      if (!SignatureVerifier.verify(
          m.key(), SigningInputs.controllerProof(operationBytes, m.id()), p.signature()))
        return false;
    }
    return seen.size() == methods.size();
  }
}
