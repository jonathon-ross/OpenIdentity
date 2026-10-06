package org.openidentity.credentials;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.AssertionPolicy;
import org.openidentity.core.IdentityId;
import org.openidentity.core.IdentityState;
import org.openidentity.core.IdentityStateV2;
import org.openidentity.core.OpenIdentityError;
import org.openidentity.core.StateHash;
import org.openidentity.core.VerificationMethod;
import org.openidentity.core.VerificationMethodId;
import org.openidentity.core.VerificationResult;
import org.openidentity.crypto.SignatureProof;
import org.openidentity.crypto.SignatureVerifier;

/** Verifies native OI-003 credentials against their exact historical assertion authority. */
public final class CredentialVerifier {
  private CredentialVerifier() {}

  /**
   * Verifies credential proofs and historical-state binding.
   *
   * <p>The supplied historical state is canonicalized and hashed. Its StateHash must equal {@code
   * issuanceStateHash}, it must belong to {@code issuer}, and it must contain an explicit
   * AssertionPolicy. Current identity state must not be substituted.
   *
   * @param credentialBytes canonical signed credential bytes
   * @param issuer issuer identity from the signed credential
   * @param issuanceStateHash historical StateHash bound into the signed credential
   * @param historicalState exact resolved historical identity state
   * @param proofs credential assertion proofs
   * @return structured cryptographic verification result
   */
  public static VerificationResult verifyResult(
      byte[] credentialBytes,
      IdentityId issuer,
      StateHash issuanceStateHash,
      IdentityState historicalState,
      List<SignatureProof> proofs) {
    Objects.requireNonNull(credentialBytes);
    Objects.requireNonNull(issuer);
    Objects.requireNonNull(issuanceStateHash);
    Objects.requireNonNull(historicalState);
    Objects.requireNonNull(proofs);

    if (!(historicalState instanceof IdentityStateV2 v2)) {
      return VerificationResult.failure(
          OpenIdentityError.NO_ASSERTION_AUTHORITY,
          "Historical state does not support AssertionPolicy");
    }
    if (!historicalState.identity().equals(issuer)) {
      return VerificationResult.failure(
          OpenIdentityError.IDENTITY_MISMATCH,
          "Historical state identity differs from credential issuer");
    }
    if (!StateHash.fromStateBytes(OpenIdentityCborEncoder.encodeState(historicalState))
        .equals(issuanceStateHash)) {
      return VerificationResult.failure(
          OpenIdentityError.INVALID_ISSUANCE_STATE_HASH,
          "issuanceStateHash does not identify the supplied historical state");
    }

    AssertionPolicy policy = v2.assertionPolicy();
    if (policy == null) {
      return VerificationResult.failure(
          OpenIdentityError.NO_ASSERTION_AUTHORITY, "Historical state contains no AssertionPolicy");
    }

    byte[] input = CredentialSigningInputs.credential(credentialBytes);
    Map<VerificationMethodId, VerificationMethod> authorized = new HashMap<>();
    for (VerificationMethod method : policy.methods()) {
      authorized.put(method.id(), method);
    }

    Set<VerificationMethodId> seen = new HashSet<>();
    int valid = 0;
    for (SignatureProof proof : proofs) {
      if (proof == null || !seen.add(proof.methodId())) {
        return VerificationResult.failure(
            OpenIdentityError.DUPLICATE_CREDENTIAL_PROOF, "Duplicate credential proof method ID");
      }
      VerificationMethod method = authorized.get(proof.methodId());
      if (method == null) {
        return VerificationResult.failure(
            OpenIdentityError.UNAUTHORIZED_CREDENTIAL_PROOF,
            "Credential proof method is absent from historical AssertionPolicy");
      }
      if (!SignatureVerifier.verify(method.key(), input, proof.signature())) {
        return VerificationResult.failure(
            OpenIdentityError.INVALID_CREDENTIAL_SIGNATURE,
            "Credential proof signature is invalid");
      }
      valid++;
    }

    if (valid < policy.threshold()) {
      return VerificationResult.failure(
          OpenIdentityError.ASSERTION_THRESHOLD_NOT_SATISFIED,
          "Credential proof set does not satisfy historical AssertionPolicy threshold");
    }
    return VerificationResult.success();
  }

  /**
   * Compatibility boolean form of {@link #verifyResult(byte[], IdentityId, StateHash,
   * IdentityState, List)}.
   *
   * @return {@code true} only when structured verification succeeds
   */
  public static boolean verify(
      byte[] credentialBytes,
      IdentityId issuer,
      StateHash issuanceStateHash,
      IdentityState historicalState,
      List<SignatureProof> proofs) {
    return verifyResult(credentialBytes, issuer, issuanceStateHash, historicalState, proofs)
        .valid();
  }
}
