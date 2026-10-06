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

class RecoveryTransitionV01Test {
  static final ObjectMapper J = new ObjectMapper();
  static final HexFormat H = HexFormat.of();

  @Test
  void r01MatchesFrozenOperationStateAndHash() throws Exception {
    run("R01", false);
  }

  @Test
  void r02ReactivatesV2AndPreservesAssertionPolicy() throws Exception {
    IdentityState result = run("R02", true);
    assertInstanceOf(IdentityStateV2.class, result);
    assertNotNull(((IdentityStateV2) result).assertionPolicy());
    assertEquals(IdentityStatus.ACTIVE, result.status());
  }

  IdentityState run(String id, boolean v2) throws Exception {
    JsonNode v = valid(id);
    RecoveryPolicy rp = recoveryPolicy(v);
    ControllerPolicy np = newController(v);
    RecoverOperation op =
        new RecoverOperation(
            IdentityId.of(hex(v, "identityHex")),
            new Sequence(BigInteger.valueOf(v.path("sequence").asLong())),
            new StateHash(MultihashSha256.of(hex(v, "previousStateHashHex"))),
            np,
            rp,
            new RecoveryCommitment(MultihashSha256.of(hex(v, "newRecoveryCommitmentHex"))));
    assertArrayEquals(hex(v, "operationBytesHex"), op.encode());
    assertArrayEquals(
        hex(v, "currentRecoveryCommitmentHex"),
        MultihashSha256.digest(OpenIdentityCborEncoder.encodeRecoveryPolicy(rp)).bytes());
    IdentityState current = source(v, v2);
    List<SignatureProof> recovery =
        List.of(
            proof(v, "currentRecoveryEd25519MethodIdHex", "recoveryEd25519SignatureHex"),
            proof(v, "currentRecoveryMlDsa65MethodIdHex", "recoveryMlDsa65SignatureHex"));
    List<SignatureProof> pop =
        List.of(proof(v, "newControllerMethodIdHex", "newControllerPopSignatureHex"));
    IdentityState result = RecoverTransition.apply(current, op, recovery, pop);
    assertArrayEquals(
        hex(v, "resultingIdentityStateHex"), OpenIdentityCborEncoder.encodeState(result));
    assertArrayEquals(
        hex(v, "resultingStateHashHex"),
        StateHash.fromStateBytes(OpenIdentityCborEncoder.encodeState(result)).bytes());
    return result;
  }

  @Test
  void ri01RecoveryNotConfiguredFails() throws Exception {
    JsonNode v = valid("R01");
    RecoverOperation op = operation(v);
    IdentityStateV1 source = (IdentityStateV1) source(v, false);
    IdentityStateV1 noRecovery =
        new IdentityStateV1(
            source.identity(), source.sequence(), source.status(), source.controllerPolicy(), null);
    assertThrows(
        IllegalArgumentException.class,
        () -> RecoverTransition.apply(noRecovery, op, recoveryProofs(v), controllerPops(v)));
  }

  @Test
  void ri03InvalidThresholdRejectedAtConstruction() throws Exception {
    JsonNode v = valid("R01");
    VerificationMethod m =
        new VerificationMethod(
            VerificationMethodId.of(hex(v, "currentRecoveryEd25519MethodIdHex")),
            Ed25519Key.of(hex(v, "currentRecoveryEd25519PublicKeyHex")));
    assertThrows(IllegalArgumentException.class, () -> new RecoveryPolicy(2, List.of(m)));
  }

  @Test
  void ri04OneOfTwoRecoveryProofsFails() throws Exception {
    JsonNode v = valid("R01");
    List<SignatureProof> p = recoveryProofs(v);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            RecoverTransition.apply(
                source(v, false), operation(v), List.of(p.get(0)), controllerPops(v)));
  }

  @Test
  void ri05DuplicateRecoveryProofFails() throws Exception {
    JsonNode v = valid("R01");
    SignatureProof p = recoveryProofs(v).get(0);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            RecoverTransition.apply(
                source(v, false), operation(v), List.of(p, p), controllerPops(v)));
  }

  @Test
  void ri06UnauthorizedRecoveryMethodFails() throws Exception {
    JsonNode v = valid("R01");
    List<SignatureProof> p = recoveryProofs(v);
    SignatureProof bad =
        new SignatureProof(
            VerificationMethodId.of(H.parseHex("000102030405060708090a0b0c0d0e0f")),
            p.get(0).signature());
    assertThrows(
        IllegalArgumentException.class,
        () ->
            RecoverTransition.apply(
                source(v, false), operation(v), List.of(bad, p.get(1)), controllerPops(v)));
  }

  @Test
  void ri07CorruptedRecoverySignatureFails() throws Exception {
    JsonNode v = valid("R01");
    List<SignatureProof> p = recoveryProofs(v);
    byte[] bad = p.get(0).signature();
    bad[0] ^= 1;
    assertThrows(
        IllegalArgumentException.class,
        () ->
            RecoverTransition.apply(
                source(v, false),
                operation(v),
                List.of(new SignatureProof(p.get(0).methodId(), bad), p.get(1)),
                controllerPops(v)));
  }

  @Test
  void ri08MissingNewControllerPopFails() throws Exception {
    JsonNode v = valid("R01");
    assertThrows(
        IllegalArgumentException.class,
        () ->
            RecoverTransition.apply(source(v, false), operation(v), recoveryProofs(v), List.of()));
  }

  @Test
  void ri09ReusedRecoveryCommitmentFails() throws Exception {
    JsonNode v = valid("R01");
    RecoverOperation good = operation(v);
    RecoverOperation bad =
        new RecoverOperation(
            good.identity(),
            good.sequence(),
            good.previousStateHash(),
            good.newControllerPolicy(),
            good.currentRecoveryPolicy(),
            ((IdentityStateV1) source(v, false)).recoveryCommitment());
    assertThrows(
        IllegalArgumentException.class,
        () -> RecoverTransition.apply(source(v, false), bad, recoveryProofs(v), controllerPops(v)));
  }

  @Test
  void ri10OrdinaryDomainSignaturesFailRecoveryVerification() throws Exception {
    JsonNode v = valid("R01");
    byte[] ordinary = SigningInputs.operation(operation(v).encode());
    List<SignatureProof> original = recoveryProofs(v);
    assertFalse(
        java.util.Arrays.equals(
            ordinary, SigningInputs.recovery(operation(v).encode(), original.get(0).methodId())));
  }

  static RecoverOperation operation(JsonNode v) {
    return new RecoverOperation(
        IdentityId.of(hex(v, "identityHex")),
        new Sequence(BigInteger.valueOf(v.path("sequence").asLong())),
        new StateHash(MultihashSha256.of(hex(v, "previousStateHashHex"))),
        newController(v),
        recoveryPolicy(v),
        new RecoveryCommitment(MultihashSha256.of(hex(v, "newRecoveryCommitmentHex"))));
  }

  static List<SignatureProof> recoveryProofs(JsonNode v) {
    return List.of(
        proof(v, "currentRecoveryEd25519MethodIdHex", "recoveryEd25519SignatureHex"),
        proof(v, "currentRecoveryMlDsa65MethodIdHex", "recoveryMlDsa65SignatureHex"));
  }

  static List<SignatureProof> controllerPops(JsonNode v) {
    return List.of(proof(v, "newControllerMethodIdHex", "newControllerPopSignatureHex"));
  }

  static IdentityState source(JsonNode v, boolean v2) {
    ControllerPolicy old = oldController(v);
    RecoveryCommitment rc =
        new RecoveryCommitment(MultihashSha256.of(hex(v, "currentRecoveryCommitmentHex")));
    long seq = v2 ? v.path("sourceSequence").asLong() : 1;
    if (v2) {
      JsonNode a;
      try {
        a = assertion("A04");
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
      AssertionPolicy ap =
          new AssertionPolicy(
              2,
              List.of(
                  new VerificationMethod(
                      VerificationMethodId.of(hex(a, "assertionEd25519MethodIdHex")),
                      Ed25519Key.of(hex(a, "assertionEd25519PublicKeyHex"))),
                  new VerificationMethod(
                      VerificationMethodId.of(hex(a, "assertionMlDsa65MethodIdHex")),
                      MlDsa65Key.of(hex(a, "assertionMlDsa65PublicKeyHex")))));
      return new IdentityStateV2(
          IdentityId.of(hex(v, "identityHex")),
          new Sequence(BigInteger.valueOf(seq)),
          IdentityStatus.DEACTIVATED,
          old,
          rc,
          ap);
    }
    return new IdentityStateV1(
        IdentityId.of(hex(v, "identityHex")),
        new Sequence(BigInteger.ONE),
        IdentityStatus.ACTIVE,
        old,
        rc);
  }

  static ControllerPolicy oldController(JsonNode v) {
    JsonNode b;
    try {
      b = crypto("V02");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    return new ControllerPolicy(
        2,
        List.of(
            new VerificationMethod(
                VerificationMethodId.of(hex(b, "ed25519MethodIdHex")),
                Ed25519Key.of(hex(b, "ed25519PublicKeyHex"))),
            new VerificationMethod(
                VerificationMethodId.of(hex(b, "mlDsa65MethodIdHex")),
                MlDsa65Key.of(hex(b, "mlDsa65PublicKeyHex")))));
  }

  static ControllerPolicy newController(JsonNode v) {
    return ControllerPolicy.single(
        new VerificationMethod(
            VerificationMethodId.of(hex(v, "newControllerMethodIdHex")),
            Ed25519Key.of(hex(v, "newControllerPublicKeyHex"))));
  }

  static RecoveryPolicy recoveryPolicy(JsonNode v) {
    return new RecoveryPolicy(
        2,
        List.of(
            new VerificationMethod(
                VerificationMethodId.of(hex(v, "currentRecoveryEd25519MethodIdHex")),
                Ed25519Key.of(hex(v, "currentRecoveryEd25519PublicKeyHex"))),
            new VerificationMethod(
                VerificationMethodId.of(hex(v, "currentRecoveryMlDsa65MethodIdHex")),
                MlDsa65Key.of(hex(v, "currentRecoveryMlDsa65PublicKeyHex")))));
  }

  static SignatureProof proof(JsonNode v, String i, String s) {
    return new SignatureProof(VerificationMethodId.of(hex(v, i)), hex(v, s));
  }

  static JsonNode valid(String id) throws Exception {
    return find("/openidentity-v0.1.1/recovery-v0.1.json", "validVectors", id);
  }

  static JsonNode crypto(String id) throws Exception {
    return find("/openidentity-v0.1.1/cryptographic-agility-v0.1.json", "valid", id);
  }

  static JsonNode assertion(String id) throws Exception {
    return find("/openidentity-v0.1.1/assertion-authority-v0.1.json", "validVectors", id);
  }

  static JsonNode find(String res, String array, String id) throws Exception {
    try (InputStream in = RecoveryTransitionV01Test.class.getResourceAsStream(res)) {
      JsonNode r = J.readTree(in);
      for (JsonNode v : r.path(array)) if (id.equals(v.path("id").asText())) return v;
      throw new AssertionError(id);
    }
  }

  static byte[] hex(JsonNode n, String f) {
    return H.parseHex(n.path(f).asText());
  }
}
