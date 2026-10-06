package org.openidentity.conformance;

import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class NormativeResourceIntegrityTest {
  static final String BASE = "/openidentity-v0.1.1/";

  record Artifact(String file, String manifest) {}

  static final Artifact[] ARTIFACTS = {
    new Artifact("identity-id-v0.1.json", "identity-id-v0.1.sha256"),
    new Artifact("state-hash-v0.1.json", "state-hash-v0.1.json.sha256"),
    new Artifact("cryptographic-agility-v0.1.json", "cryptographic-agility-v0.1.sha256"),
    new Artifact("signature-envelope-v0.1.json", "signature-envelope-v0.1.json.sha256"),
    new Artifact("assertion-authority-v0.1.json", "assertion-authority-v0.1.json.sha256"),
    new Artifact("credential-v0.1.json", "credential-v0.1.json.sha256"),
    new Artifact(
        "w3c-credential-projection-v0.1.json", "w3c-credential-projection-v0.1.json.sha256"),
    new Artifact("recovery-v0.1.json", "recovery-v0.1.json.sha256")
  };

  @Test
  void allPinnedProtocolV011ResourcesMatchAuthoritativeSha256() throws Exception {
    for (Artifact artifact : ARTIFACTS) {
      byte[] data = read(artifact.file());
      byte[] manifest = read(artifact.manifest());
      String expected = new String(manifest, StandardCharsets.UTF_8).trim().split("\\s+")[0];
      String actual = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
      assertEquals(expected, actual, artifact.file());
    }
  }

  static byte[] read(String file) throws Exception {
    try (InputStream in = NormativeResourceIntegrityTest.class.getResourceAsStream(BASE + file)) {
      if (in == null) throw new AssertionError("Missing normative resource " + file);
      return in.readAllBytes();
    }
  }
}
