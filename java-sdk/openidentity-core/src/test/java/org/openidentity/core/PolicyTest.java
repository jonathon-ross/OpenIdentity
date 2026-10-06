package org.openidentity.core;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;

class PolicyTest {
  @Test
  void canonicalizesMethodOrderAndRejectsDuplicates() {
    byte[] a = new byte[16], b = new byte[16];
    a[0] = (byte) 0x80;
    b[0] = 0x7f;
    VerificationMethod high =
        new VerificationMethod(VerificationMethodId.of(a), Ed25519Key.of(new byte[32]));
    VerificationMethod low =
        new VerificationMethod(VerificationMethodId.of(b), Ed25519Key.of(new byte[32]));
    ControllerPolicy policy = new ControllerPolicy(2, List.of(high, low));
    assertEquals(low.id(), policy.methods().get(0).id());
    assertEquals(high.id(), policy.methods().get(1).id());
    assertThrows(IllegalArgumentException.class, () -> new ControllerPolicy(2, List.of(low, low)));
    assertThrows(IllegalArgumentException.class, () -> new ControllerPolicy(3, List.of(low, high)));
  }
}
