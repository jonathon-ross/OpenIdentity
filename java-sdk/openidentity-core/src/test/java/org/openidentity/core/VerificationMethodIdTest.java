package org.openidentity.core;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class VerificationMethodIdTest {
  @Test
  void comparesUsingUnsignedBytewiseLexicographicOrdering() {
    byte[] low = new byte[16];
    byte[] high = new byte[16];
    low[0] = 0x7f;
    high[0] = (byte) 0x80;

    assertTrue(VerificationMethodId.of(low).compareTo(VerificationMethodId.of(high)) < 0);
  }

  @Test
  void requiresExactly16Bytes() {
    assertThrows(IllegalArgumentException.class, () -> VerificationMethodId.of(new byte[15]));
    assertThrows(IllegalArgumentException.class, () -> VerificationMethodId.of(new byte[17]));
  }
}
