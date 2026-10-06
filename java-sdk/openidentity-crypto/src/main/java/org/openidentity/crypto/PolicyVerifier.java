package org.openidentity.crypto;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.openidentity.core.AuthorityPolicy;
import org.openidentity.core.VerificationMethod;
import org.openidentity.core.VerificationMethodId;

public final class PolicyVerifier {
  private PolicyVerifier() {}

  public static boolean verify(
      AuthorityPolicy policy, byte[] signingInput, List<SignatureProof> proofs) {
    Objects.requireNonNull(policy, "policy");
    Objects.requireNonNull(signingInput, "signingInput");
    Objects.requireNonNull(proofs, "proofs");

    Map<VerificationMethodId, VerificationMethod> authorized = new HashMap<>();
    for (VerificationMethod method : policy.methods()) authorized.put(method.id(), method);

    Set<VerificationMethodId> seen = new HashSet<>();
    int valid = 0;
    for (SignatureProof proof : proofs) {
      if (proof == null || !seen.add(proof.methodId())) return false;
      VerificationMethod method = authorized.get(proof.methodId());
      if (method == null) return false;
      if (SignatureVerifier.verify(method.key(), signingInput, proof.signature())) valid++;
    }
    return valid >= policy.threshold();
  }
}
