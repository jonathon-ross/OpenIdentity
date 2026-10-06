package org.openidentity.credentials;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

public final class W3cCredentialProjection {
  public static final int VERSION = 1;

  private W3cCredentialProjection() {}

  public static Map<String, Object> basicV1(OpenIdentityCredential c, byte[] securedCredential) {
    Objects.requireNonNull(c);
    Objects.requireNonNull(securedCredential);
    if (!"https://openidentity.foundation/test/credentials/basic/v1".equals(c.profile()))
      throw new IllegalArgumentException("Unsupported Basic v1 projection profile");
    String subjectText = new String(c.subject(), StandardCharsets.UTF_8);
    if (!"alice@example.test".equals(subjectText))
      throw new IllegalArgumentException("Invalid Basic v1 subject");
    Map<String, Object> claims = c.claims();
    if (claims.size() != 3
        || !claims.containsKey("name")
        || !claims.containsKey("role")
        || !Boolean.TRUE.equals(claims.get("active")))
      throw new IllegalArgumentException("Invalid Basic v1 claims");
    LinkedHashMap<String, Object> subject = new LinkedHashMap<>();
    subject.put("id", "urn:openidentity:test-subject:" + Multibase.base64Url(c.subject()));
    subject.put("name", claims.get("name"));
    subject.put("role", claims.get("role"));
    subject.put("active", claims.get("active"));
    LinkedHashMap<String, Object> p = new LinkedHashMap<>();
    p.put(
        "@context",
        List.of(
            "https://www.w3.org/ns/credentials/v2",
            "https://openidentity.foundation/ns/v2",
            "https://openidentity.foundation/test/credentials/basic/v1/context"));
    p.put("id", "urn:openidentity:credential:" + Multibase.base64Url(c.id()));
    p.put(
        "type",
        List.of("VerifiableCredential", "OpenIdentityCredential", "OpenIdentityBasicCredential"));
    p.put("issuer", "did:open:" + Multibase.base58Btc(c.issuer().bytes()));
    p.put("validFrom", Instant.ofEpochSecond(c.validFrom()).toString());
    if (c.validUntil() != null)
      p.put("validUntil", Instant.ofEpochSecond(c.validUntil()).toString());
    p.put("credentialSubject", subject);
    p.put("openIdentityCredentialProfile", c.profile());
    p.put("openIdentityIssuanceStateHash", Multibase.base58Btc(c.issuanceStateHash().bytes()));
    p.put("openIdentitySecuredCredential", Multibase.base64Url(securedCredential));
    return Collections.unmodifiableMap(p);
  }
}
