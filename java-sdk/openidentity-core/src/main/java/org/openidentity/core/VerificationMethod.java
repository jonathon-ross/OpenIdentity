package org.openidentity.core;

import java.util.Objects;

/**
 * Binds a stable verification-method identifier to an authoritative cryptographic public key.
 *
 * @param id 16-byte method identifier
 * @param key supported COSE key
 */
public record VerificationMethod(VerificationMethodId id, CoseKey key)
    implements Comparable<VerificationMethod> {
  /** Validates required method fields. */
  public VerificationMethod {
    Objects.requireNonNull(id, "id");
    Objects.requireNonNull(key, "key");
  }

  @Override
  public int compareTo(VerificationMethod other) {
    return id.compareTo(other.id);
  }
}
