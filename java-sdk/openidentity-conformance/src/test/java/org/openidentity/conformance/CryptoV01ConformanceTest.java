package org.openidentity.conformance;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.openidentity.core.ControllerPolicy;
import org.openidentity.core.Ed25519Key;
import org.openidentity.core.MlDsa65Key;
import org.openidentity.core.VerificationMethod;
import org.openidentity.core.VerificationMethodId;
import org.openidentity.crypto.Ed25519;
import org.openidentity.crypto.MlDsa65;
import org.openidentity.crypto.PolicyVerifier;
import org.openidentity.crypto.SignatureProof;
import org.openidentity.crypto.SigningInputs;

class CryptoV01ConformanceTest {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final HexFormat HEX = HexFormat.of();
  private static final String BASE = "/openidentity-v0.1.1/";

  @Test
  void cryptographicAgilityResourceMatchesPublishedChecksum() throws Exception {
    byte[] bytes = resource("cryptographic-agility-v0.1.json");
    String expected =
        new String(resource("cryptographic-agility-v0.1.sha256"), StandardCharsets.UTF_8)
            .trim()
            .split("\\s+")[0];
    assertEquals(expected, HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)));
  }

  @Test
  void v02HybridCreateSignaturesVerify() throws Exception {
    JsonNode v = vector("V02");
    byte[] operation = hex(v, "operationBytesHex");
    byte[] signingInput = hex(v, "signingInputHex");
    assertArrayEquals(signingInput, SigningInputs.operation(operation));
    assertTrue(
        Ed25519.verify(
            Ed25519Key.of(hex(v, "ed25519PublicKeyHex")),
            signingInput,
            hex(v, "ed25519SignatureHex")));
    assertTrue(
        MlDsa65.verify(
            MlDsa65Key.of(hex(v, "mlDsa65PublicKeyHex")),
            signingInput,
            hex(v, "mlDsa65SignatureHex")));
    assertEquals(1952, hex(v, "mlDsa65PublicKeyHex").length);
    assertEquals(3309, hex(v, "mlDsa65SignatureHex").length);
  }

  @Test
  void se02ThroughSe05AndSe10RejectOperationMutations() throws Exception {
    JsonNode root = JSON.readTree(resource("signature-envelope-v0.1.json"));
    JsonNode se01 = signatureVector(root, "SE01");
    Ed25519Key key = Ed25519Key.of(hex(se01, "controllerPublicKeyHex"));
    byte[] originalSignature = hex(se01, "authorizationSignatureHex");

    for (String id : new String[] {"SE02", "SE03", "SE04", "SE05", "SE10"}) {
      JsonNode v = signatureVector(root, id);
      byte[] operation = hex(v, "operationBytesHex");
      byte[] expectedInput = hex(v, "mutatedSigningInputHex");
      assertArrayEquals(expectedInput, SigningInputs.operation(operation), id + " signing input");
      assertFalse(Ed25519.verify(key, expectedInput, originalSignature), id + " must reject");
    }
  }

  @Test
  void se06RejectsOrdinaryAuthorizationAsControllerProof() throws Exception {
    JsonNode root = JSON.readTree(resource("signature-envelope-v0.1.json"));
    JsonNode se01 = signatureVector(root, "SE01");
    JsonNode v = signatureVector(root, "SE06");
    Ed25519Key key = Ed25519Key.of(hex(se01, "controllerPublicKeyHex"));
    byte[] operation = hex(v, "operationBytesHex");
    VerificationMethodId id = VerificationMethodId.of(hex(se01, "controllerMethodIdHex"));
    byte[] required = SigningInputs.controllerProof(operation, id);
    assertArrayEquals(hex(v, "requiredSigningInputHex"), required);
    assertFalse(Ed25519.verify(key, required, hex(v, "substitutedSignatureHex")));
  }

  @Test
  void se07RejectsControllerProofAsOrdinaryAuthorization() throws Exception {
    JsonNode root = JSON.readTree(resource("signature-envelope-v0.1.json"));
    JsonNode se01 = signatureVector(root, "SE01");
    JsonNode v = signatureVector(root, "SE07");
    Ed25519Key key = Ed25519Key.of(hex(se01, "controllerPublicKeyHex"));
    byte[] required = SigningInputs.operation(hex(v, "operationBytesHex"));
    assertArrayEquals(hex(v, "requiredSigningInputHex"), required);
    assertFalse(Ed25519.verify(key, required, hex(v, "substitutedSignatureHex")));
  }

  @Test
  void se08RejectsRecoveryAuthorizationAsOrdinaryAuthorization() throws Exception {
    JsonNode root = JSON.readTree(resource("signature-envelope-v0.1.json"));
    JsonNode se01 = signatureVector(root, "SE01");
    JsonNode v = signatureVector(root, "SE08");
    Ed25519Key key = Ed25519Key.of(hex(se01, "controllerPublicKeyHex"));
    byte[] required = SigningInputs.operation(hex(v, "operationBytesHex"));
    assertArrayEquals(hex(v, "requiredSigningInputHex"), required);
    assertFalse(Ed25519.verify(key, required, hex(v, "substitutedSignatureHex")));
  }

  @Test
  void se09RejectsSigningStructureVersionMutation() throws Exception {
    JsonNode root = JSON.readTree(resource("signature-envelope-v0.1.json"));
    JsonNode se01 = signatureVector(root, "SE01");
    JsonNode v = signatureVector(root, "SE09");
    Ed25519Key key = Ed25519Key.of(hex(se01, "controllerPublicKeyHex"));
    byte[] mutated = hex(v, "mutatedSigningInputHex");
    assertFalse(Ed25519.verify(key, mutated, hex(v, "authorizationSignatureHex")));
  }

  @Test
  void v02HybridPolicyRequiresBothEd25519AndMlDsa65Proofs() throws Exception {
    JsonNode v = vector("V02");
    byte[] signingInput = hex(v, "signingInputHex");

    VerificationMethod ed =
        new VerificationMethod(
            VerificationMethodId.of(hex(v, "ed25519MethodIdHex")),
            Ed25519Key.of(hex(v, "ed25519PublicKeyHex")));
    VerificationMethod ml =
        new VerificationMethod(
            VerificationMethodId.of(hex(v, "mlDsa65MethodIdHex")),
            MlDsa65Key.of(hex(v, "mlDsa65PublicKeyHex")));

    ControllerPolicy policy = new ControllerPolicy(2, List.of(ed, ml));
    SignatureProof edProof = new SignatureProof(ed.id(), hex(v, "ed25519SignatureHex"));
    SignatureProof mlProof = new SignatureProof(ml.id(), hex(v, "mlDsa65SignatureHex"));

    assertTrue(PolicyVerifier.verify(policy, signingInput, List.of(edProof, mlProof)));
    assertFalse(PolicyVerifier.verify(policy, signingInput, List.of(edProof)));
    assertFalse(PolicyVerifier.verify(policy, signingInput, List.of(mlProof)));
  }

  @Test
  void v02HybridPolicyRejectsDuplicateProofInsteadOfWeakeningThreshold() throws Exception {
    JsonNode v = vector("V02");
    byte[] signingInput = hex(v, "signingInputHex");
    VerificationMethod ed =
        new VerificationMethod(
            VerificationMethodId.of(hex(v, "ed25519MethodIdHex")),
            Ed25519Key.of(hex(v, "ed25519PublicKeyHex")));
    VerificationMethod ml =
        new VerificationMethod(
            VerificationMethodId.of(hex(v, "mlDsa65MethodIdHex")),
            MlDsa65Key.of(hex(v, "mlDsa65PublicKeyHex")));
    ControllerPolicy policy = new ControllerPolicy(2, List.of(ed, ml));
    SignatureProof edProof = new SignatureProof(ed.id(), hex(v, "ed25519SignatureHex"));
    assertFalse(PolicyVerifier.verify(policy, signingInput, List.of(edProof, edProof)));
  }

  private static JsonNode signatureVector(JsonNode root, String id) {
    for (JsonNode v : root.path("vectors")) if (id.equals(v.path("id").asText())) return v;
    throw new AssertionError("Missing signature vector " + id);
  }

  private static JsonNode vector(String id) throws Exception {
    JsonNode root = JSON.readTree(resource("cryptographic-agility-v0.1.json"));
    for (JsonNode v : root.path("valid")) if (id.equals(v.path("id").asText())) return v;
    throw new AssertionError("Missing vector " + id);
  }

  private static byte[] hex(JsonNode node, String field) {
    return HEX.parseHex(node.path(field).asText());
  }

  private static byte[] resource(String name) throws Exception {
    try (InputStream in = CryptoV01ConformanceTest.class.getResourceAsStream(BASE + name)) {
      if (in == null) throw new AssertionError("Missing resource " + name);
      return in.readAllBytes();
    }
  }
}
