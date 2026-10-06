package org.openidentity.credentials;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.*;
import java.io.*;
import java.util.*;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.openidentity.core.*;

class W3cProjectionV01Test {
  static final ObjectMapper J = new ObjectMapper();
  static final HexFormat H = HexFormat.of();

  @Test
  void wp01MatchesFrozenProjection() throws Exception {
    check("WP01", "C01");
  }

  @Test
  void wp02MatchesFrozenProjectionAndContainsNoProof() throws Exception {
    Map<String, Object> p = check("WP02", "C02");
    assertFalse(p.containsKey("proof"));
  }

  Map<String, Object> check(String wid, String cid) throws Exception {
    JsonNode c = find("/openidentity-v0.1.1/credential-v0.1.json", "validVectors", cid),
        w = find("/openidentity-v0.1.1/w3c-credential-projection-v0.1.json", "validVectors", wid);
    OpenIdentityCredential cred = credential(c);
    Map<String, Object> p = W3cCredentialProjection.basicV1(cred, hex(c, "securedCredentialHex"));
    assertEquals(J.valueToTree(p), w.path("w3cCredential"));
    return p;
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

  static JsonNode find(String r, String a, String id) throws Exception {
    try (InputStream in = W3cProjectionV01Test.class.getResourceAsStream(r)) {
      JsonNode root = J.readTree(in);
      for (JsonNode v : root.path(a)) if (id.equals(v.path("id").asText())) return v;
      throw new AssertionError(id);
    }
  }

  static byte[] hex(JsonNode n, String f) {
    return H.parseHex(n.path(f).asText());
  }
}
