package org.openidentity.credentials;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.*;
import java.io.*;
import java.math.BigInteger;
import java.util.*;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.*;
import org.openidentity.crypto.*;

class CredentialV01ConformanceTest {
  static final ObjectMapper J = new ObjectMapper();
  static final HexFormat H = HexFormat.of();

  @Test
  void c01SingleCredentialMatchesAndVerifies() throws Exception {
    check("C01", "A01", false);
  }

  @Test
  void c02HybridCredentialMatchesAndRequiresTwoProofs() throws Exception {
    JsonNode c = check("C02", "A04", true);
    IdentityStateV2 state = state(c, "A04", true);
    OpenIdentityCredential cred = credential(c);
    List<SignatureProof> p = proofs(c);
    assertFalse(
        CredentialVerifier.verify(
            cred.encode(), cred.issuer(), cred.issuanceStateHash(), state, List.of(p.get(0))));
  }

  JsonNode check(String cid, String aid, boolean hybrid) throws Exception {
    JsonNode c = credentialVector(cid);
    OpenIdentityCredential cred = credential(c);
    byte[] bytes = cred.encode();
    assertArrayEquals(hex(c, "credentialBytesHex"), bytes);
    assertArrayEquals(
        hex(c, "credentialSigningInputHex"), CredentialSigningInputs.credential(bytes));
    IdentityStateV2 historical = state(c, aid, hybrid);
    assertArrayEquals(
        hex(c, "historicalIdentityStateHex"), OpenIdentityCborEncoder.encodeState(historical));
    assertTrue(
        CredentialVerifier.verify(
            bytes, cred.issuer(), cred.issuanceStateHash(), historical, proofs(c)));
    return c;
  }

  @Test
  void ci01HybridNeedsThreshold() throws Exception {
    JsonNode c = credentialVector("C02");
    OpenIdentityCredential cred = credential(c);
    IdentityStateV2 s = state(c, "A04", true);
    List<SignatureProof> p = proofs(c);
    assertFalse(
        CredentialVerifier.verify(
            cred.encode(), cred.issuer(), cred.issuanceStateHash(), s, List.of(p.get(0))));
  }

  @Test
  void ci02DuplicateProofRejected() throws Exception {
    JsonNode c = credentialVector("C02");
    OpenIdentityCredential cred = credential(c);
    IdentityStateV2 s = state(c, "A04", true);
    SignatureProof p = proofs(c).get(0);
    assertFalse(
        CredentialVerifier.verify(
            cred.encode(), cred.issuer(), cred.issuanceStateHash(), s, List.of(p, p)));
  }

  @Test
  void ci03UnauthorizedExtraProofRejected() throws Exception {
    JsonNode c = credentialVector("C02");
    OpenIdentityCredential cred = credential(c);
    IdentityStateV2 s = state(c, "A04", true);
    List<SignatureProof> p = new ArrayList<>(proofs(c));
    p.add(
        new SignatureProof(
            VerificationMethodId.of(H.parseHex("000102030405060708090a0b0c0d0e0f")), new byte[64]));
    assertFalse(
        CredentialVerifier.verify(cred.encode(), cred.issuer(), cred.issuanceStateHash(), s, p));
  }

  @Test
  void ci04CorruptEd25519Rejected() throws Exception {
    JsonNode c = credentialVector("C01");
    OpenIdentityCredential cred = credential(c);
    IdentityStateV2 s = state(c, "A01", false);
    SignatureProof p = proofs(c).get(0);
    byte[] bad = p.signature();
    bad[0] ^= 1;
    assertFalse(
        CredentialVerifier.verify(
            cred.encode(),
            cred.issuer(),
            cred.issuanceStateHash(),
            s,
            List.of(new SignatureProof(p.methodId(), bad))));
  }

  @Test
  void ci05CorruptMlDsaRejected() throws Exception {
    JsonNode c = credentialVector("C02");
    OpenIdentityCredential cred = credential(c);
    IdentityStateV2 s = state(c, "A04", true);
    List<SignatureProof> p = proofs(c);
    byte[] bad = p.get(1).signature();
    bad[0] ^= 1;
    assertFalse(
        CredentialVerifier.verify(
            cred.encode(),
            cred.issuer(),
            cred.issuanceStateHash(),
            s,
            List.of(p.get(0), new SignatureProof(p.get(1).methodId(), bad))));
  }

  @Test
  void ci06WrongIssuanceStateHashRejected() throws Exception {
    JsonNode c = credentialVector("C01");
    OpenIdentityCredential cred = credential(c);
    IdentityStateV2 s = state(c, "A01", false);
    byte[] bad = cred.issuanceStateHash().bytes();
    bad[33] ^= 1;
    assertFalse(
        CredentialVerifier.verify(
            cred.encode(), cred.issuer(), new StateHash(MultihashSha256.of(bad)), s, proofs(c)));
  }

  @Test
  void ci07OperationDomainSignatureDoesNotVerifyAsCredential() throws Exception {
    JsonNode c = credentialVector("C01");
    assertFalse(
        java.util.Arrays.equals(
            CredentialSigningInputs.credential(hex(c, "credentialBytesHex")),
            org.openidentity.crypto.SigningInputs.operation(hex(c, "credentialBytesHex"))));
  }

  @Test
  void ci08ReboundUnauthorizedMethodRejected() throws Exception {
    JsonNode c = credentialVector("C01");
    OpenIdentityCredential cred = credential(c);
    IdentityStateV2 s = state(c, "A01", false);
    SignatureProof p = proofs(c).get(0);
    VerificationMethodId other =
        VerificationMethodId.of(H.parseHex("404142434445464748494a4b4c4d4e4f"));
    assertFalse(
        CredentialVerifier.verify(
            cred.encode(),
            cred.issuer(),
            cred.issuanceStateHash(),
            s,
            List.of(new SignatureProof(other, p.signature()))));
  }

  @Test
  void ci09ModifiedClaimsInvalidateSignature() throws Exception {
    JsonNode c = credentialVector("C01");
    OpenIdentityCredential original = credential(c);
    Map<String, Object> changed = new HashMap<>(original.claims());
    changed.put("role", "administrator");
    OpenIdentityCredential modified =
        new OpenIdentityCredential(
            hex(c, "credentialIdHex"),
            original.issuer(),
            original.issuanceStateHash(),
            c.path("validFrom").asLong(),
            c.path("validUntil").asLong(),
            c.path("credentialProfile").asText(),
            hex(c, "credentialSubjectHex"),
            changed);
    assertFalse(
        CredentialVerifier.verify(
            modified.encode(),
            modified.issuer(),
            modified.issuanceStateHash(),
            state(c, "A01", false),
            proofs(c)));
  }

  @Test
  void ci10NoAssertionAuthorityRejected() throws Exception {
    JsonNode c = credentialVector("C01");
    JsonNode a = assertionVector("A03");
    ControllerPolicy cp = controller(a);
    IdentityStateV2 noAssertion =
        new IdentityStateV2(
            IdentityId.of(hex(c, "issuerIdentityHex")),
            new Sequence(BigInteger.valueOf(4)),
            IdentityStatus.ACTIVE,
            cp,
            null,
            null);
    OpenIdentityCredential bound =
        new OpenIdentityCredential(
            hex(c, "credentialIdHex"),
            IdentityId.of(hex(c, "issuerIdentityHex")),
            StateHash.fromStateBytes(OpenIdentityCborEncoder.encodeState(noAssertion)),
            c.path("validFrom").asLong(),
            c.path("validUntil").asLong(),
            c.path("credentialProfile").asText(),
            hex(c, "credentialSubjectHex"),
            credential(c).claims());
    assertFalse(
        CredentialVerifier.verify(
            bound.encode(), bound.issuer(), bound.issuanceStateHash(), noAssertion, proofs(c)));
  }

  static OpenIdentityCredential credential(JsonNode c) {
    Map<String, Object> claims = new HashMap<>();
    c.path("claims")
        .fields()
        .forEachRemaining(
            e -> {
              JsonNode v = e.getValue();
              claims.put(
                  e.getKey(),
                  v.isBoolean()
                      ? v.booleanValue()
                      : v.isIntegralNumber() ? v.bigIntegerValue() : v.asText());
            });
    return new OpenIdentityCredential(
        hex(c, "credentialIdHex"),
        IdentityId.of(hex(c, "issuerIdentityHex")),
        new StateHash(MultihashSha256.of(hex(c, "issuanceStateHashHex"))),
        c.path("validFrom").asLong(),
        c.has("validUntil") ? c.path("validUntil").asLong() : null,
        c.path("credentialProfile").asText(),
        hex(c, "credentialSubjectHex"),
        claims);
  }

  static IdentityStateV2 state(JsonNode c, String aid, boolean hybrid) throws Exception {
    JsonNode a = assertionVector(aid);
    ControllerPolicy cp = controller(a);
    AssertionPolicy ap;
    if (hybrid)
      ap =
          new AssertionPolicy(
              2,
              List.of(
                  new VerificationMethod(
                      VerificationMethodId.of(hex(a, "assertionEd25519MethodIdHex")),
                      Ed25519Key.of(hex(a, "assertionEd25519PublicKeyHex"))),
                  new VerificationMethod(
                      VerificationMethodId.of(hex(a, "assertionMlDsa65MethodIdHex")),
                      MlDsa65Key.of(hex(a, "assertionMlDsa65PublicKeyHex")))));
    else
      ap =
          AssertionPolicy.single(
              new VerificationMethod(
                  VerificationMethodId.of(hex(a, "assertionEd25519MethodIdHex")),
                  Ed25519Key.of(hex(a, "assertionEd25519PublicKeyHex"))));
    return new IdentityStateV2(
        IdentityId.of(hex(c, "issuerIdentityHex")),
        new Sequence(BigInteger.valueOf(a.path("sequence").asLong())),
        IdentityStatus.ACTIVE,
        cp,
        null,
        ap);
  }

  static ControllerPolicy controller(JsonNode a) throws Exception {
    JsonNode cv = crypto();
    return new ControllerPolicy(
        2,
        List.of(
            new VerificationMethod(
                VerificationMethodId.of(hex(cv, "ed25519MethodIdHex")),
                Ed25519Key.of(hex(cv, "ed25519PublicKeyHex"))),
            new VerificationMethod(
                VerificationMethodId.of(hex(cv, "mlDsa65MethodIdHex")),
                MlDsa65Key.of(hex(cv, "mlDsa65PublicKeyHex")))));
  }

  static List<SignatureProof> proofs(JsonNode c) {
    List<SignatureProof> p = new ArrayList<>();
    if (c.has("assertionMethodIdHex"))
      p.add(
          new SignatureProof(
              VerificationMethodId.of(hex(c, "assertionMethodIdHex")),
              hex(c, "credentialSignatureHex")));
    else {
      p.add(
          new SignatureProof(
              VerificationMethodId.of(hex(c, "ed25519MethodIdHex")),
              hex(c, "ed25519SignatureHex")));
      p.add(
          new SignatureProof(
              VerificationMethodId.of(hex(c, "mlDsa65MethodIdHex")),
              hex(c, "mlDsa65SignatureHex")));
    }
    return p;
  }

  static JsonNode credentialVector(String id) throws Exception {
    return find("/openidentity-v0.1.1/credential-v0.1.json", "validVectors", id);
  }

  static JsonNode assertionVector(String id) throws Exception {
    return find("/openidentity-v0.1.1/assertion-authority-v0.1.json", "validVectors", id);
  }

  static JsonNode crypto() throws Exception {
    return find("/openidentity-v0.1.1/cryptographic-agility-v0.1.json", "valid", "V02");
  }

  static JsonNode find(String r, String arr, String id) throws Exception {
    try (InputStream in = CredentialV01ConformanceTest.class.getResourceAsStream(r)) {
      JsonNode root = J.readTree(in);
      for (JsonNode v : root.path(arr)) if (id.equals(v.path("id").asText())) return v;
      throw new AssertionError(id);
    }
  }

  static byte[] hex(JsonNode n, String f) {
    return H.parseHex(n.path(f).asText());
  }
}
