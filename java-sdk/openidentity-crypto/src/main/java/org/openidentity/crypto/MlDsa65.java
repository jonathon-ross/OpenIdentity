package org.openidentity.crypto;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Objects;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openidentity.core.MlDsa65Key;

public final class MlDsa65 {
  public static final int SIGNATURE_LENGTH = 3309;
  private static final String PROVIDER = "BC";
  private static final String ALGORITHM = "MLDSA";

  static {
    if (Security.getProvider(PROVIDER) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private MlDsa65() {}

  public static boolean verify(MlDsa65Key key, byte[] message, byte[] signature) {
    Objects.requireNonNull(key, "key");
    Objects.requireNonNull(message, "message");
    Objects.requireNonNull(signature, "signature");
    if (signature.length != SIGNATURE_LENGTH) return false;
    try {
      KeyFactory factory = KeyFactory.getInstance(ALGORITHM, PROVIDER);
      PublicKey publicKey =
          factory.generatePublic(
              new MLDSAPublicKeySpec(MLDSAParameterSpec.ml_dsa_65, key.publicKey()));
      Signature verifier = Signature.getInstance(ALGORITHM, PROVIDER);
      verifier.initVerify(publicKey);
      verifier.update(message);
      return verifier.verify(signature);
    } catch (Exception e) {
      throw new IllegalStateException("Unable to verify ML-DSA-65 signature", e);
    }
  }
}
