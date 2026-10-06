package org.openidentity.crypto;

import java.util.Objects;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.openidentity.core.Ed25519Key;

public final class Ed25519 {
  private Ed25519() {}

  public static boolean verify(Ed25519Key key, byte[] message, byte[] signature) {
    Objects.requireNonNull(key, "key");
    Objects.requireNonNull(message, "message");
    Objects.requireNonNull(signature, "signature");
    if (signature.length != 64) return false;
    Ed25519Signer verifier = new Ed25519Signer();
    verifier.init(false, new Ed25519PublicKeyParameters(key.publicKey(), 0));
    verifier.update(message, 0, message.length);
    return verifier.verifySignature(signature);
  }
}
