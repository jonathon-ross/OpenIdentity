package org.openidentity.crypto;

import java.util.Objects;
import org.openidentity.core.CoseKey;
import org.openidentity.core.Ed25519Key;
import org.openidentity.core.MlDsa65Key;

public final class SignatureVerifier {
  private SignatureVerifier() {}

  public static boolean verify(CoseKey key, byte[] message, byte[] signature) {
    Objects.requireNonNull(key, "key");
    if (key instanceof Ed25519Key ed) return Ed25519.verify(ed, message, signature);
    if (key instanceof MlDsa65Key ml) return MlDsa65.verify(ml, message, signature);
    throw new IllegalArgumentException("Unsupported OpenIdentity v0.1 COSE key");
  }
}
