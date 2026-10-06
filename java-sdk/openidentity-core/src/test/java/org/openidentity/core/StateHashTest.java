package org.openidentity.core;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class StateHashTest {
  private static byte[] hex(String value) {
    return HexFormat.of().parseHex(value);
  }

  @Test
  void stateHashUsesSha256MultihashEnvelope() {
    byte[] stateBytes = hex("a10101");
    byte[] expected = MultihashSha256.digest(stateBytes).bytes();
    assertEquals(34, expected.length);
    assertEquals(0x12, expected[0] & 0xff);
    assertEquals(0x20, expected[1] & 0xff);
  }

  @Test
  void rejectsRawDigestAsStateHash() {
    assertThrows(IllegalArgumentException.class, () -> MultihashSha256.of(new byte[32]));
  }
}
