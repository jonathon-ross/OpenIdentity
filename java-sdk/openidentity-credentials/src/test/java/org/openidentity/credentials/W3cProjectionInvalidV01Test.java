package org.openidentity.credentials;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.*;
import java.io.*;
import java.util.*;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.openidentity.core.*;

class W3cProjectionInvalidV01Test {
  static final ObjectMapper J = new ObjectMapper();
  static final HexFormat H = HexFormat.of();

  @Test
  void wpi01ThroughWpi08TamperedProjectionRejected() throws Exception {
    JsonNode c = cred("C01"), w = proj("WP01");
    OpenIdentityCredential nativeCred = credential(c);
    byte[] secured = hex(c, "securedCredentialHex");
    String[] fields = {
      "issuer",
      "id",
      "validFrom",
      "openIdentityIssuanceStateHash",
      "openIdentitySecuredCredential",
      "credentialSubject",
      "credentialSubject",
      "@context"
    };
    for (int i = 0; i < fields.length; i++) {
      Map<String, Object> p = map(w.path("w3cCredential"));
      String f = fields[i];
      if (i == 5) {
        ((Map<String, Object>) p.get("credentialSubject")).put("id", "urn:bad");
      } else if (i == 6) {
        ((Map<String, Object>) p.get("credentialSubject")).put("role", "administrator");
      } else if (i == 7) {
        p.put(
            "@context",
            List.of(
                "https://www.w3.org/ns/credentials/v2", "https://openidentity.foundation/ns/v1"));
      } else p.put(f, "tampered");
      assertFalse(W3cProjectionValidator.validateBasicV1(p, nativeCred, secured), "WPI0" + (i + 1));
    }
  }

  @Test
  void wpi09W3cProofIsRejected() throws Exception {
    JsonNode c = cred("C01"), w = proj("WP01");
    Map<String, Object> p = map(w.path("w3cCredential"));
    p.put("proof", Map.of("type", "DataIntegrityProof"));
    assertFalse(
        W3cProjectionValidator.validateBasicV1(p, credential(c), hex(c, "securedCredentialHex")));
  }

  @Test
  void wpi10ProjectionCannotReplaceHistoricalNativeVerification() throws Exception {
    JsonNode c = cred("C01"), w = proj("WP01");
    Map<String, Object> p = map(w.path("w3cCredential"));
    assertTrue(
        W3cProjectionValidator.validateBasicV1(p, credential(c), hex(c, "securedCredentialHex")));
    byte[] bad = credential(c).issuanceStateHash().bytes();
    bad[33] ^= 1;
    assertNotEquals(credential(c).issuanceStateHash(), new StateHash(MultihashSha256.of(bad)));
  }

  static Map<String, Object> map(JsonNode n) {
    return J.convertValue(n, new TypeReference<LinkedHashMap<String, Object>>() {});
  }

  static OpenIdentityCredential credential(JsonNode c) {
    Map<String, Object> claims = new HashMap<>();
    c.path("claims")
        .fields()
        .forEachRemaining(
            e -> {
              JsonNode v = e.getValue();
              claims.put(e.getKey(), v.isBoolean() ? v.booleanValue() : v.asText());
            });
    return new OpenIdentityCredential(
        hex(c, "credentialIdHex"),
        IdentityId.of(hex(c, "issuerIdentityHex")),
        new StateHash(MultihashSha256.of(hex(c, "issuanceStateHashHex"))),
        c.path("validFrom").asLong(),
        c.path("validUntil").asLong(),
        c.path("credentialProfile").asText(),
        hex(c, "credentialSubjectHex"),
        claims);
  }

  static JsonNode cred(String id) throws Exception {
    return find("/openidentity-v0.1.1/credential-v0.1.json", "validVectors", id);
  }

  static JsonNode proj(String id) throws Exception {
    return find("/openidentity-v0.1.1/w3c-credential-projection-v0.1.json", "validVectors", id);
  }

  static JsonNode find(String r, String a, String id) throws Exception {
    try (InputStream in = W3cProjectionInvalidV01Test.class.getResourceAsStream(r)) {
      JsonNode root = J.readTree(in);
      for (JsonNode v : root.path(a)) if (id.equals(v.path("id").asText())) return v;
      throw new AssertionError(id);
    }
  }

  static byte[] hex(JsonNode n, String f) {
    return H.parseHex(n.path(f).asText());
  }
}
