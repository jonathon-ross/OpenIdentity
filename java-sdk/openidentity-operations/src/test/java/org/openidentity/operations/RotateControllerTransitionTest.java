package org.openidentity.operations;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.*;
import java.io.*;
import java.math.BigInteger;
import java.util.*;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.openidentity.core.*;
import org.openidentity.crypto.*;

class RotateControllerTransitionTest {
  static final ObjectMapper J = new ObjectMapper();
  static final HexFormat H = HexFormat.of();

  @Test
  void v04RotateProducesFrozenStateAndHash() throws Exception {
    JsonNode v = vector("V04");
    ControllerPolicy oldp = policy(v, "old");
    ControllerPolicy newp = policy(v, "new");
    IdentityStateV1 current =
        new IdentityStateV1(
            IdentityId.of(hex(v, "identityHex")),
            new Sequence(BigInteger.ONE),
            IdentityStatus.ACTIVE,
            oldp,
            null);
    RotateControllerOperation op =
        new RotateControllerOperation(
            current.identity(),
            new Sequence(BigInteger.valueOf(2)),
            new StateHash(MultihashSha256.of(hex(v, "previousStateHashHex"))),
            newp);
    List<SignatureProof> auth =
        List.of(
            proof(v, "oldEd25519MethodIdHex", "oldEd25519AuthorizationSignatureHex"),
            proof(v, "oldMlDsa65MethodIdHex", "oldMlDsa65AuthorizationSignatureHex"));
    List<SignatureProof> pop =
        List.of(
            proof(v, "newEd25519MethodIdHex", "newEd25519PopSignatureHex"),
            proof(v, "newMlDsa65MethodIdHex", "newMlDsa65PopSignatureHex"));
    IdentityState result = RotateControllerTransition.apply(current, op, auth, pop);
    assertArrayEquals(
        hex(v, "resultingIdentityStateHex"),
        org.openidentity.cbor.OpenIdentityCborEncoder.encodeState(result));
    assertArrayEquals(
        hex(v, "resultingStateHashHex"),
        RotateControllerTransition.resultingStateHash(current, op, auth, pop).bytes());
  }

  @Test
  void rotatePreservesV2AssertionPolicy() throws Exception {
    java.security.KeyPairGenerator generator =
        java.security.KeyPairGenerator.getInstance("Ed25519");
    java.security.KeyPair oldKey = generator.generateKeyPair();
    java.security.KeyPair newKey = generator.generateKeyPair();

    VerificationMethod oldMethod =
        new VerificationMethod(
            VerificationMethodId.of(H.parseHex("000102030405060708090a0b0c0d0e0f")),
            Ed25519Key.of(rawEd25519((java.security.interfaces.EdECPublicKey) oldKey.getPublic())));
    VerificationMethod newMethod =
        new VerificationMethod(
            VerificationMethodId.of(H.parseHex("101112131415161718191a1b1c1d1e1f")),
            Ed25519Key.of(rawEd25519((java.security.interfaces.EdECPublicKey) newKey.getPublic())));
    AssertionPolicy assertion =
        AssertionPolicy.single(
            new VerificationMethod(
                VerificationMethodId.of(H.parseHex("202122232425262728292a2b2c2d2e2f")),
                oldMethod.key()));

    IdentityStateV2 current =
        new IdentityStateV2(
            IdentityId.of(
                H.parseHex("303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")),
            Sequence.of(1),
            IdentityStatus.ACTIVE,
            ControllerPolicy.single(oldMethod),
            null,
            assertion);

    StateHash predecessor =
        StateHash.fromStateBytes(
            org.openidentity.cbor.OpenIdentityCborEncoder.encodeState(current));
    RotateControllerOperation operation =
        new RotateControllerOperation(
            current.identity(), Sequence.of(2), predecessor, ControllerPolicy.single(newMethod));

    SignatureProof authorization =
        sign(oldMethod.id(), oldKey, SigningInputs.operation(operation.encode()));
    SignatureProof possession =
        sign(
            newMethod.id(),
            newKey,
            SigningInputs.controllerProof(operation.encode(), newMethod.id()));

    IdentityState result =
        RotateControllerTransition.apply(
            current, operation, List.of(authorization), List.of(possession));

    IdentityStateV2 v2 = assertInstanceOf(IdentityStateV2.class, result);
    assertEquals(assertion, v2.assertionPolicy());
    assertEquals(operation.proposedControllerPolicy(), v2.controllerPolicy());
    assertEquals(Sequence.of(2), v2.sequence());
  }

  private static SignatureProof sign(
      VerificationMethodId methodId, java.security.KeyPair keyPair, byte[] input) throws Exception {
    java.security.Signature signer = java.security.Signature.getInstance("Ed25519");
    signer.initSign(keyPair.getPrivate());
    signer.update(input);
    return new SignatureProof(methodId, signer.sign());
  }

  private static byte[] rawEd25519(java.security.interfaces.EdECPublicKey publicKey) {
    java.security.spec.EdECPoint point = publicKey.getPoint();
    byte[] y = point.getY().toByteArray();
    byte[] encoded = new byte[32];
    for (int i = 0; i < Math.min(y.length, 32); i++) {
      encoded[i] = y[y.length - 1 - i];
    }
    if (point.isXOdd()) encoded[31] |= (byte) 0x80;
    return encoded;
  }

  @Test
  void v04RejectsMissingNewControllerPop() throws Exception {
    JsonNode v = vector("V04");
    ControllerPolicy oldp = policy(v, "old"), newp = policy(v, "new");
    IdentityStateV1 current =
        new IdentityStateV1(
            IdentityId.of(hex(v, "identityHex")),
            new Sequence(BigInteger.ONE),
            IdentityStatus.ACTIVE,
            oldp,
            null);
    RotateControllerOperation op =
        new RotateControllerOperation(
            current.identity(),
            new Sequence(BigInteger.TWO),
            new StateHash(MultihashSha256.of(hex(v, "previousStateHashHex"))),
            newp);
    List<SignatureProof> auth =
        List.of(
            proof(v, "oldEd25519MethodIdHex", "oldEd25519AuthorizationSignatureHex"),
            proof(v, "oldMlDsa65MethodIdHex", "oldMlDsa65AuthorizationSignatureHex"));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            RotateControllerTransition.apply(
                current,
                op,
                auth,
                List.of(proof(v, "newEd25519MethodIdHex", "newEd25519PopSignatureHex"))));
  }

  static ControllerPolicy policy(JsonNode v, String p) {
    return new ControllerPolicy(
        2,
        List.of(
            new VerificationMethod(
                VerificationMethodId.of(hex(v, p + "Ed25519MethodIdHex")),
                Ed25519Key.of(hex(v, p + "Ed25519PublicKeyHex"))),
            new VerificationMethod(
                VerificationMethodId.of(hex(v, p + "MlDsa65MethodIdHex")),
                MlDsa65Key.of(hex(v, p + "MlDsa65PublicKeyHex")))));
  }

  static SignatureProof proof(JsonNode v, String id, String sig) {
    return new SignatureProof(VerificationMethodId.of(hex(v, id)), hex(v, sig));
  }

  static JsonNode vector(String id) throws Exception {
    try (InputStream in =
        RotateControllerTransitionTest.class.getResourceAsStream(
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
