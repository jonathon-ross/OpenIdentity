package org.openidentity.conformance;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.openidentity.cbor.OpenIdentityCborDecoder;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.IdentityState;
import org.openidentity.core.StateHash;

class StateHashV01ConformanceTest {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final HexFormat HEX = HexFormat.of();
  private static final String RESOURCE = "/openidentity-v0.1.1/state-hash-v0.1.json";

  @Test
  void frozenVectorResourceMatchesPublishedChecksum() throws Exception {
    byte[] bytes = resourceBytes(RESOURCE);
    String checksum =
        new String(resourceBytes(RESOURCE + ".sha256"), StandardCharsets.UTF_8)
            .trim()
            .split("\\s+")[0];
    assertEquals(checksum, HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)));
  }

  @Test
  void sh01ThroughSh10ProducePublishedStateHashes() throws Exception {
    JsonNode root = JSON.readTree(resourceBytes(RESOURCE));
    assertEquals("OpenIdentity StateHash", root.path("specification").asText());
    assertEquals("0.1", root.path("version").asText());
    assertEquals(10, root.path("vectors").size());

    int expected = 1;
    for (JsonNode vector : root.path("vectors")) {
      assertEquals("SH%02d".formatted(expected++), vector.path("id").asText());
      byte[] stateBytes = HEX.parseHex(vector.path("stateBytesHex").asText());
      byte[] published = HEX.parseHex(vector.path("stateHashHex").asText());
      assertArrayEquals(
          published, StateHash.fromStateBytes(stateBytes).bytes(), vector.path("id").asText());
      assertEquals(34, published.length);
    }
  }

  @Test
  void sh01ThroughSh10RoundTripThroughSdkModelByteForByte() throws Exception {
    JsonNode root = JSON.readTree(resourceBytes(RESOURCE));
    for (JsonNode vector : root.path("vectors")) {
      byte[] published = HEX.parseHex(vector.path("stateBytesHex").asText());
      IdentityState decoded = OpenIdentityCborDecoder.decodeState(published);
      byte[] independentlyEncoded = OpenIdentityCborEncoder.encodeState(decoded);
      assertArrayEquals(published, independentlyEncoded, vector.path("id").asText());
      assertArrayEquals(
          HEX.parseHex(vector.path("stateHashHex").asText()),
          StateHash.fromStateBytes(independentlyEncoded).bytes(),
          vector.path("id").asText() + " reconstructed StateHash");
    }
  }

  @Test
  void sh09RejectsRawDigestAsEquivalentStateHash() throws Exception {
    JsonNode sh09 = vector("SH09");
    byte[] authoritative = HEX.parseHex(sh09.path("stateHashHex").asText());
    byte[] raw = HEX.parseHex(sh09.path("rawSha256DigestHex").asText());
    assertEquals(34, authoritative.length);
    assertEquals(32, raw.length);
    assertFalse(java.util.Arrays.equals(authoritative, raw));
  }

  @Test
  void sh10RejectsAlternateRepresentationHashAsAuthoritative() throws Exception {
    JsonNode sh10 = vector("SH10");
    assertNotEquals(
        sh10.path("stateHashHex").asText(), sh10.path("alternateMultihashHex").asText());
    assertFalse(sh10.path("alternateHashIsAuthoritativeStateHash").asBoolean());
  }

  private static JsonNode vector(String id) throws Exception {
    for (JsonNode vector : JSON.readTree(resourceBytes(RESOURCE)).path("vectors")) {
      if (id.equals(vector.path("id").asText())) return vector;
    }
    throw new AssertionError("Missing vector " + id);
  }

  private static byte[] resourceBytes(String path) throws Exception {
    try (InputStream in = StateHashV01ConformanceTest.class.getResourceAsStream(path)) {
      if (in == null) throw new AssertionError("Missing test resource " + path);
      return in.readAllBytes();
    }
  }
}
