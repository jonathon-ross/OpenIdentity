package org.openidentity.operations;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.openidentity.core.*;

class OperationVectorV01Test {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final HexFormat HEX = HexFormat.of();

  private static byte[] h(String s) {
    return HEX.parseHex(s);
  }

  @Test
  void v02HybridCreateMatchesFrozenOperationBytes() throws Exception {
    JsonNode v = vector("V02");
    CreateOperation op =
        new CreateOperation(
            IdentityId.of(hex(v, "identityHex")),
            new ControllerPolicy(
                2,
                List.of(
                    new VerificationMethod(
                        VerificationMethodId.of(hex(v, "ed25519MethodIdHex")),
                        Ed25519Key.of(hex(v, "ed25519PublicKeyHex"))),
                    new VerificationMethod(
                        VerificationMethodId.of(hex(v, "mlDsa65MethodIdHex")),
                        MlDsa65Key.of(hex(v, "mlDsa65PublicKeyHex"))))),
            null);
    assertArrayEquals(hex(v, "operationBytesHex"), op.encode());
  }

  @Test
  void v04RotateControllerMatchesFrozenOperationBytes() throws Exception {
    JsonNode v = vector("V04");
    VerificationMethod ed =
        new VerificationMethod(
            VerificationMethodId.of(h("202122232425262728292a2b2c2d2e2f")),
            Ed25519Key.of(h("2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d")));
    VerificationMethod ml =
        new VerificationMethod(
            VerificationMethodId.of(h("303132333435363738393a3b3c3d3e3f")),
            MlDsa65Key.of(extractNewMlDsaKey(v)));
    RotateControllerOperation op =
        new RotateControllerOperation(
            IdentityId.of(hex(v, "identityHex")),
            new Sequence(BigInteger.valueOf(v.path("sequence").asLong())),
            new StateHash(MultihashSha256.of(hex(v, "previousStateHashHex"))),
            new ControllerPolicy(2, List.of(ed, ml)));
    assertArrayEquals(hex(v, "operationBytesHex"), op.encode());
  }

  @Test
  void v02CreateDecodesAndReencodesByteForByte() throws Exception {
    JsonNode v = vector("V02");
    byte[] expected = hex(v, "operationBytesHex");
    OpenIdentityOperation decoded = OpenIdentityOperationDecoder.decode(expected);
    assertInstanceOf(CreateOperation.class, decoded);
    assertArrayEquals(expected, decoded.encode());
  }

  @Test
  void v04RotateDecodesAndReencodesByteForByte() throws Exception {
    JsonNode v = vector("V04");
    byte[] expected = hex(v, "operationBytesHex");
    OpenIdentityOperation decoded = OpenIdentityOperationDecoder.decode(expected);
    assertInstanceOf(RotateControllerOperation.class, decoded);
    assertArrayEquals(expected, decoded.encode());
  }

  @Test
  void operationDecoderRejectsTrailingBytes() throws Exception {
    byte[] canonical = hex(vector("V02"), "operationBytesHex");
    byte[] trailing = java.util.Arrays.copyOf(canonical, canonical.length + 1);
    assertThrows(
        IllegalArgumentException.class, () -> OpenIdentityOperationDecoder.decode(trailing));
  }

  private static byte[] extractNewMlDsaKey(JsonNode v) {
    String policy = v.path("newControllerPolicyHex").asText();
    if (policy.isEmpty()) policy = v.path("proposedControllerPolicyHex").asText();
    byte[] expectedOperation = hex(v, "operationBytesHex");
    byte[] marker = h("5907a0");
    int pos = lastIndexOf(expectedOperation, marker);
    if (pos < 0) throw new AssertionError("ML-DSA key marker not found");
    return java.util.Arrays.copyOfRange(
        expectedOperation, pos + marker.length, pos + marker.length + MlDsa65Key.LENGTH);
  }

  private static int lastIndexOf(byte[] data, byte[] needle) {
    outer:
    for (int i = data.length - needle.length; i >= 0; i--) {
      for (int j = 0; j < needle.length; j++) if (data[i + j] != needle[j]) continue outer;
      return i;
    }
    return -1;
  }

  private static JsonNode vector(String id) throws Exception {
    try (InputStream in =
        OperationVectorV01Test.class.getResourceAsStream(
            "/openidentity-v0.1.1/cryptographic-agility-v0.1.json")) {
      if (in == null) throw new AssertionError("Missing vector resource");
      JsonNode root = JSON.readTree(in);
      for (JsonNode v : root.path("valid")) if (id.equals(v.path("id").asText())) return v;
      throw new AssertionError("Missing vector " + id);
    }
  }

  private static byte[] hex(JsonNode n, String f) {
    return HEX.parseHex(n.path(f).asText());
  }
}
