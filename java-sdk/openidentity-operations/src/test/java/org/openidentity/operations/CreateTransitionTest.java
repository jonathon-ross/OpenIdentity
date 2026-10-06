package org.openidentity.operations;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.*;
import org.openidentity.crypto.SignatureProof;

class CreateTransitionTest {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final HexFormat H = HexFormat.of();

  @Test
  void v02AuthorizedCreateProducesFrozenStateAndHash() throws Exception {
    JsonNode v = vector("V02");
    VerificationMethod ed =
        new VerificationMethod(
            VerificationMethodId.of(hex(v, "ed25519MethodIdHex")),
            Ed25519Key.of(hex(v, "ed25519PublicKeyHex")));
    VerificationMethod ml =
        new VerificationMethod(
            VerificationMethodId.of(hex(v, "mlDsa65MethodIdHex")),
            MlDsa65Key.of(hex(v, "mlDsa65PublicKeyHex")));
    CreateOperation op =
        new CreateOperation(
            IdentityId.of(hex(v, "identityHex")), new ControllerPolicy(2, List.of(ed, ml)), null);
    List<SignatureProof> proofs =
        List.of(
            new SignatureProof(ed.id(), hex(v, "ed25519SignatureHex")),
            new SignatureProof(ml.id(), hex(v, "mlDsa65SignatureHex")));
    IdentityStateV1 state = CreateTransition.apply(op, proofs);
    assertEquals(IdentityStatus.ACTIVE, state.status());
    assertEquals(1, state.stateVersion());
    assertArrayEquals(hex(v, "identityStateHex"), OpenIdentityCborEncoder.encodeState(state));
    assertArrayEquals(
        hex(v, "stateHashHex"), CreateTransition.resultingStateHash(op, proofs).bytes());
  }

  @Test
  void v02CreateRejectsOneOfTwoProofs() throws Exception {
    JsonNode v = vector("V02");
    VerificationMethod ed =
        new VerificationMethod(
            VerificationMethodId.of(hex(v, "ed25519MethodIdHex")),
            Ed25519Key.of(hex(v, "ed25519PublicKeyHex")));
    VerificationMethod ml =
        new VerificationMethod(
            VerificationMethodId.of(hex(v, "mlDsa65MethodIdHex")),
            MlDsa65Key.of(hex(v, "mlDsa65PublicKeyHex")));
    CreateOperation op =
        new CreateOperation(
            IdentityId.of(hex(v, "identityHex")), new ControllerPolicy(2, List.of(ed, ml)), null);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            CreateTransition.apply(
                op, List.of(new SignatureProof(ed.id(), hex(v, "ed25519SignatureHex")))));
  }

  private static JsonNode vector(String id) throws Exception {
    try (InputStream in =
        CreateTransitionTest.class.getResourceAsStream(
            "/openidentity-v0.1.1/cryptographic-agility-v0.1.json")) {
      JsonNode root = JSON.readTree(in);
      for (JsonNode v : root.path("valid")) if (id.equals(v.path("id").asText())) return v;
      throw new AssertionError(id);
    }
  }

  private static byte[] hex(JsonNode n, String f) {
    return H.parseHex(n.path(f).asText());
  }
}
