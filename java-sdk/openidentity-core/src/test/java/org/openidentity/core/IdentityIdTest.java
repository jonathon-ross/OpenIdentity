package org.openidentity.core;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class IdentityIdTest {
  @Test
  void requiresExactly32BytesAndDefensivelyCopies() {
    byte[] source = new byte[32];
    source[0] = 1;

    IdentityId id = IdentityId.of(source);
    source[0] = 2;

    assertEquals(1, id.bytes()[0]);
    byte[] returned = id.bytes();
    returned[0] = 3;
    assertEquals(1, id.bytes()[0]);

    assertThrows(IllegalArgumentException.class, () -> IdentityId.of(new byte[31]));
    assertThrows(IllegalArgumentException.class, () -> IdentityId.of(new byte[33]));
  }
}
