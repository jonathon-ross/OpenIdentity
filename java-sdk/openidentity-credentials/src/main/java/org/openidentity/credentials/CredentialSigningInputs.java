package org.openidentity.credentials;

import java.util.Objects;
import org.openidentity.cbor.OpenIdentityCborEncoder;

/** Constructs the domain-separated signing input for native OpenIdentity credentials. */
public final class CredentialSigningInputs {
  private CredentialSigningInputs() {}

  /**
   * Builds {@code ["OpenIdentity Credential", 1, CredentialBytes]} as deterministic CBOR.
   *
   * @param credentialBytes complete canonical native credential bytes
   * @return credential signing-structure bytes
   */
  public static byte[] credential(byte[] credentialBytes) {
    Objects.requireNonNull(credentialBytes);
    return OpenIdentityCborEncoder.encodeCredentialSigningInput(credentialBytes);
  }
}
