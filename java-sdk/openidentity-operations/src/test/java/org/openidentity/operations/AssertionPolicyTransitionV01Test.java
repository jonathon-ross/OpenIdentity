package org.openidentity.operations;

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

class AssertionPolicyTransitionV01Test {
  static final ObjectMapper J = new ObjectMapper();
  static final HexFormat H = HexFormat.of();

  @Test
  void a01UpgradesV1ToV2AndMatchesFrozenState() throws Exception {
    JsonNode v = valid("A01");
    IdentityStateV1 current = v1Source(v);
    AssertionPolicy ap = singleAssertion(v);
    SetAssertionPolicyOperation op = op(v, ap);
    IdentityStateV2 result =
        SetAssertionPolicyTransition.apply(current, op, controllerProofs(v), assertionPops(v));
    assertEquals(2, result.stateVersion());
    assertArrayEquals(hex(v, "operationBytesHex"), op.encode());
    assertArrayEquals(
        hex(v, "resultingIdentityStateHex"), OpenIdentityCborEncoder.encodeState(result));
    assertArrayEquals(
        hex(v, "resultingStateHashHex"),
        StateHash.fromStateBytes(OpenIdentityCborEncoder.encodeState(result)).bytes());
  }

  @Test
  void a03RemovalLeavesV2WithNoAssertionAuthority() throws Exception {
    JsonNode v = valid("A03"), src = valid("A02");
    IdentityStateV2 current = v2Source(v, src);
    SetAssertionPolicyOperation op = op(v, null);
    IdentityStateV2 result =
        SetAssertionPolicyTransition.apply(current, op, controllerProofs(v), List.of());
    assertNull(result.assertionPolicy());
    assertEquals(2, result.stateVersion());
    assertArrayEquals(
        hex(v, "resultingIdentityStateHex"), OpenIdentityCborEncoder.encodeState(result));
  }

  @Test
  void a04HybridAssertionPolicyRequiresBothPops() throws Exception {
    JsonNode v = valid("A04"), src = valid("A03");
    IdentityStateV2 current = v2Source(v, src);
    AssertionPolicy ap = hybridAssertion(v);
    SetAssertionPolicyOperation op = op(v, ap);
    List<SignatureProof> pops = assertionPops(v);
    IdentityStateV2 result =
        SetAssertionPolicyTransition.apply(current, op, controllerProofs(v), pops);
    assertArrayEquals(
        hex(v, "resultingIdentityStateHex"), OpenIdentityCborEncoder.encodeState(result));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SetAssertionPolicyTransition.apply(
                current, op, controllerProofs(v), List.of(pops.get(0))));
  }

  @Test
  void ai01MissingControllerProofFails() throws Exception {
    JsonNode v = valid("A01");
    SetAssertionPolicyOperation op = op(v, singleAssertion(v));
    List<SignatureProof> auth = controllerProofs(v);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SetAssertionPolicyTransition.apply(
                v1Source(v), op, List.of(auth.get(0)), assertionPops(v)));
  }

  @Test
  void ai03InvalidAssertionPopFails() throws Exception {
    JsonNode v = valid("A01");
    List<SignatureProof> pops = assertionPops(v);
    byte[] bad = pops.get(0).signature();
    bad[0] ^= 1;
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SetAssertionPolicyTransition.apply(
                v1Source(v),
                op(v, singleAssertion(v)),
                controllerProofs(v),
                List.of(new SignatureProof(pops.get(0).methodId(), bad))));
  }

  @Test
  void ai04WrongAssertionMethodIdFails() throws Exception {
    JsonNode v = valid("A01");
    SignatureProof p = assertionPops(v).get(0);
    VerificationMethodId wrong =
        VerificationMethodId.of(H.parseHex("404142434445464748494a4b4c4d4e4f"));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SetAssertionPolicyTransition.apply(
                v1Source(v),
                op(v, singleAssertion(v)),
                controllerProofs(v),
                List.of(new SignatureProof(wrong, p.signature()))));
  }

  @Test
  void ai05InvalidPreviousStateHashFails() throws Exception {
    JsonNode v = valid("A01");
    byte[] bad = hex(v, "previousStateHashHex");
    bad[33] ^= 1;
    SetAssertionPolicyOperation badOp =
        new SetAssertionPolicyOperation(
            IdentityId.of(hex(v, "identityHex")),
            new Sequence(BigInteger.TWO),
            new StateHash(MultihashSha256.of(bad)),
            singleAssertion(v));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SetAssertionPolicyTransition.apply(
                v1Source(v), badOp, controllerProofs(v), assertionPops(v)));
  }

  @Test
  void ai06InvalidSequenceFails() throws Exception {
    JsonNode v = valid("A01");
    SetAssertionPolicyOperation badOp =
        new SetAssertionPolicyOperation(
            IdentityId.of(hex(v, "identityHex")),
            new Sequence(BigInteger.valueOf(3)),
            new StateHash(MultihashSha256.of(hex(v, "previousStateHashHex"))),
            singleAssertion(v));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SetAssertionPolicyTransition.apply(
                v1Source(v), badOp, controllerProofs(v), assertionPops(v)));
  }

  @Test
  void ai07InvalidControllerSignatureFails() throws Exception {
    JsonNode v = valid("A01");
    List<SignatureProof> auth = controllerProofs(v);
    byte[] bad = auth.get(0).signature();
    bad[0] ^= 1;
    List<SignatureProof> changed =
        List.of(new SignatureProof(auth.get(0).methodId(), bad), auth.get(1));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SetAssertionPolicyTransition.apply(
                v1Source(v), op(v, singleAssertion(v)), changed, assertionPops(v)));
  }

  @Test
  void ai08DuplicateAssertionMethodRejectedAtPolicyConstruction() throws Exception {
    JsonNode v = valid("A01");
    VerificationMethod m =
        new VerificationMethod(
            VerificationMethodId.of(hex(v, "assertionEd25519MethodIdHex")),
            Ed25519Key.of(hex(v, "assertionEd25519PublicKeyHex")));
    assertThrows(IllegalArgumentException.class, () -> new AssertionPolicy(1, List.of(m, m)));
  }

  @Test
  void ai09InvalidAssertionThresholdRejectedAtPolicyConstruction() throws Exception {
    JsonNode v = valid("A01");
    VerificationMethod m =
        new VerificationMethod(
            VerificationMethodId.of(hex(v, "assertionEd25519MethodIdHex")),
            Ed25519Key.of(hex(v, "assertionEd25519PublicKeyHex")));
    assertThrows(IllegalArgumentException.class, () -> new AssertionPolicy(2, List.of(m)));
  }

  @Test
  void ai10SetAssertionPolicyFromV2AlwaysProducesV2() throws Exception {
    JsonNode v = valid("A02"), src = valid("A01");
    IdentityStateV2 current = v2Source(v, src);
    IdentityStateV2 result =
        SetAssertionPolicyTransition.apply(
            current, op(v, singleAssertion(v)), controllerProofs(v), assertionPops(v));
    assertEquals(2, result.stateVersion());
  }

  @Test
  void ai02MissingAssertionPopFails() throws Exception {
    JsonNode v = valid("A01");
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SetAssertionPolicyTransition.apply(
                v1Source(v), op(v, singleAssertion(v)), controllerProofs(v), List.of()));
  }

  static IdentityStateV1 v1Source(JsonNode v) {
    return new IdentityStateV1(
        IdentityId.of(hex(v, "identityHex")),
        new Sequence(BigInteger.ONE),
        IdentityStatus.ACTIVE,
        controllerPolicy(v),
        null);
  }

  static IdentityStateV2 v2Source(JsonNode v, JsonNode src) {
    AssertionPolicy prior = src.path("assertionPolicy").isNull() ? null : singleAssertion(src);
    return new IdentityStateV2(
        IdentityId.of(hex(v, "identityHex")),
        new Sequence(BigInteger.valueOf(v.path("sequence").asLong() - 1)),
        IdentityStatus.ACTIVE,
        controllerPolicy(v),
        null,
        prior);
  }

  static SetAssertionPolicyOperation op(JsonNode v, AssertionPolicy ap) {
    return new SetAssertionPolicyOperation(
        IdentityId.of(hex(v, "identityHex")),
        new Sequence(BigInteger.valueOf(v.path("sequence").asLong())),
        new StateHash(MultihashSha256.of(hex(v, "previousStateHashHex"))),
        ap);
  }

  static ControllerPolicy controllerPolicy(JsonNode v) {
    JsonNode base;
    try {
      base = crypto("V02");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    return new ControllerPolicy(
        2,
        List.of(
            new VerificationMethod(
                VerificationMethodId.of(hex(base, "ed25519MethodIdHex")),
                Ed25519Key.of(hex(base, "ed25519PublicKeyHex"))),
            new VerificationMethod(
                VerificationMethodId.of(hex(base, "mlDsa65MethodIdHex")),
                MlDsa65Key.of(hex(base, "mlDsa65PublicKeyHex")))));
  }

  static AssertionPolicy singleAssertion(JsonNode v) {
    return AssertionPolicy.single(
        new VerificationMethod(
            VerificationMethodId.of(hex(v, "assertionEd25519MethodIdHex")),
            Ed25519Key.of(hex(v, "assertionEd25519PublicKeyHex"))));
  }

  static AssertionPolicy hybridAssertion(JsonNode v) {
    return new AssertionPolicy(
        2,
        List.of(
            new VerificationMethod(
                VerificationMethodId.of(hex(v, "assertionEd25519MethodIdHex")),
                Ed25519Key.of(hex(v, "assertionEd25519PublicKeyHex"))),
            new VerificationMethod(
                VerificationMethodId.of(hex(v, "assertionMlDsa65MethodIdHex")),
                MlDsa65Key.of(hex(v, "assertionMlDsa65PublicKeyHex")))));
  }

  static List<SignatureProof> controllerProofs(JsonNode v) {
    JsonNode base;
    try {
      base = crypto("V02");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    return List.of(
        new SignatureProof(
            VerificationMethodId.of(hex(base, "ed25519MethodIdHex")),
            hex(v, "controllerEd25519AuthorizationSignatureHex")),
        new SignatureProof(
            VerificationMethodId.of(hex(base, "mlDsa65MethodIdHex")),
            hex(v, "controllerMlDsa65AuthorizationSignatureHex")));
  }

  static List<SignatureProof> assertionPops(JsonNode v) {
    List<SignatureProof> p = new ArrayList<>();
    p.add(
        new SignatureProof(
            VerificationMethodId.of(hex(v, "assertionEd25519MethodIdHex")),
            hex(v, "assertionEd25519PopSignatureHex")));
    if (v.has("assertionMlDsa65MethodIdHex"))
      p.add(
          new SignatureProof(
              VerificationMethodId.of(hex(v, "assertionMlDsa65MethodIdHex")),
              hex(v, "assertionMlDsa65PopSignatureHex")));
    return p;
  }

  static JsonNode valid(String id) throws Exception {
    try (InputStream in =
        AssertionPolicyTransitionV01Test.class.getResourceAsStream(
            "/openidentity-v0.1.1/assertion-authority-v0.1.json")) {
      JsonNode r = J.readTree(in);
      for (JsonNode v : r.path("validVectors")) if (id.equals(v.path("id").asText())) return v;
      throw new AssertionError(id);
    }
  }

  static JsonNode crypto(String id) throws Exception {
    try (InputStream in =
        AssertionPolicyTransitionV01Test.class.getResourceAsStream(
            "/openidentity-v0.1.1/cryptographic-agility-v0.1.json")) {
      JsonNode r = J.readTree(in);
      for (JsonNode v : r.path("valid")) if (id.equals(v.path("id").asText())) return v;
      throw new AssertionError(id);
    }
  }

  static byte[] hex(JsonNode n, String f) {
    return H.parseHex(n.path(f).asText());
  }
}
