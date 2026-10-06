package org.openidentity.crypto;

import java.util.Arrays;
import java.util.Objects;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.VerificationMethodId;

/** Immutable method-identified raw signature used by OpenIdentity proof collections. */
public final class SignatureProof {
  private final VerificationMethodId methodId;
  private final byte[] signature;

  /**
   * Creates a proof.
   *
   * @param methodId verification method that produced the signature
   * @param signature raw algorithm-specific signature bytes
   * @throws IllegalArgumentException if the signature is empty
   */
  public SignatureProof(VerificationMethodId methodId, byte[] signature) {
    this.methodId = Objects.requireNonNull(methodId, "methodId");
    this.signature = Objects.requireNonNull(signature, "signature").clone();
    if (signature.length == 0) {
      throw new IllegalArgumentException("signature must not be empty");
    }
  }

  /**
   * @return verification method identifier
   */
  public VerificationMethodId methodId() {
    return methodId;
  }

  /**
   * @return defensive copy of raw signature bytes
   */
  public byte[] signature() {
    return signature.clone();
  }

  /**
   * Encodes this proof using the canonical OpenIdentity proof map.
   *
   * @return deterministic CBOR proof bytes
   */
  public byte[] encode() {
    return OpenIdentityCborEncoder.encodeSignatureProof(methodId.bytes(), signature);
  }

  @Override
  public boolean equals(Object other) {
    return other instanceof SignatureProof p
        && methodId.equals(p.methodId)
        && Arrays.equals(signature, p.signature);
  }

  @Override
  public int hashCode() {
    return 31 * methodId.hashCode() + Arrays.hashCode(signature);
  }
}
