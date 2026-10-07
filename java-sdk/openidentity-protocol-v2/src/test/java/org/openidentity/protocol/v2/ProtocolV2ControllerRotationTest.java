package org.openidentity.protocol.v2;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;

final class ProtocolV2ControllerRotationTest {
  static final HexFormat H = HexFormat.of();
  static final byte[] PREV =
      H.parseHex(
          "a50102025820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0304040105a201010281a20150000102030405060708090a0b0c0d0e0f02a4010103272006215820597ae3a921f5261aa6580bb2378c4e1380e2fc02c43ff05f1c7c624580e2bb15");
  static final byte[] SIGNED =
      H.parseHex(
          "a301a601020202035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f04050558221220e3315da5bd4f8aedb2e310b0b362d5f1ff2b9cca074d94c9ad71c66cf066c68c06a101a201010281a20150101112131415161718191a1b1c1d1e1f02a40101032720062158206f63c8642ffe361a210b08cd144422df834f57e36a745e15090604eeb08b94be0281a20150000102030405060708090a0b0c0d0e0f0258404733c2f2a24baa9f7c8b512d916c1d93aad5870c3f5b2a5975f4f1186ccc93f8500f98381cf3d8d4fdcba59dcf39321a65c176f80c5801971bb16d7e26a9800e0381a20150101112131415161718191a1b1c1d1e1f0258402f69c9d8d37fe99969f9091a036b39ec89e5437fd2bb3c077bc4f7de66ea886ae48fd4a94512a1fa9b675d67e1b8ae9704c82c04319d21403d73c551e1a02e01");
  static final String
      STATE =
          "a70103025820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0305040105a201010281a20150101112131415161718191a1b1c1d1e1f02a40101032720062158206f63c8642ffe361a210b08cd144422df834f57e36a745e15090604eeb08b94be08a1010009a10100",
      HASH = "1220a811795d3fe3c954743217db801677d6fd90a463c8349fdaddc934fbf5fb7053";

  @Test
  void v322RotatesControllerExactly() {
    var t = ProtocolV2TransitionVerifier.verifyAndApply(PREV, SIGNED);
    assertEquals(4, t.predecessorSequence());
    assertEquals(5, t.successorSequence());
    assertEquals(STATE, H.formatHex(t.successorStateBytes()));
    assertEquals(HASH, H.formatHex(t.successorStateHash()));
  }

  @Test
  void tamperedOldControllerAuthorizationRejected() {
    byte[] x = SIGNED.clone();
    int i =
        indexOf(
            x,
            H.parseHex(
                "4733c2f2a24baa9f7c8b512d916c1d93aad5870c3f5b2a5975f4f1186ccc93f8500f98381cf3d8d4fdcba59dcf39321a65c176f80c5801971bb16d7e26a9800e"));
    assertTrue(i > 0);
    x[i] ^= 1;
    assertThrows(
        IllegalArgumentException.class, () -> ProtocolV2TransitionVerifier.verifyAndApply(PREV, x));
  }

  @Test
  void tamperedNewControllerPopRejected() {
    byte[] x = SIGNED.clone();
    x[x.length - 1] ^= 1;
    assertThrows(
        IllegalArgumentException.class, () -> ProtocolV2TransitionVerifier.verifyAndApply(PREV, x));
  }

  @Test
  void wrongPredecessorRejected() {
    byte[] x = PREV.clone();
    x[x.length - 1] ^= 1;
    assertThrows(
        IllegalArgumentException.class,
        () -> ProtocolV2TransitionVerifier.verifyAndApply(x, SIGNED));
  }

  static int indexOf(byte[] a, byte[] n) {
    outer:
    for (int i = 0; i <= a.length - n.length; i++) {
      for (int j = 0; j < n.length; j++) if (a[i + j] != n[j]) continue outer;
      return i;
    }
    return -1;
  }
}
