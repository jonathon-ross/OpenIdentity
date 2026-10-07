package org.openidentity.protocol.v2;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;

final class ProtocolV2TransitionVerifierTest {
  static final HexFormat H = HexFormat.of();
  static final byte[] PREV =
      H.parseHex(
          "a50102025820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0301040105a201010281a20150000102030405060708090a0b0c0d0e0f02a4010103272006215820e17c1ebe48de2b7f7a34cb50662d2ff458a11fa909debf300a70cecda9392f55");
  static final byte[] SIGNED =
      H.parseHex(
          "a301a601020206035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0402055822122069bfcfca0c3736a7dc068134de2a0937461da7f7e07f752f208c34d935adbf9206a101a201010281a20150101112131415161718191a1b1c1d1e1f02a4010103272006215820753fd15f9c77d97898e4385827d759ca52650c8594aa3f9e5051a0a89db31c2b0281a20150000102030405060708090a0b0c0d0e0f025840f5b7a19c8e31f9d54e1a14f0afdcfc6246ac01c27eb436944ae2651fd2a5f124196c488c5d1567b1ef5aeb33349c807dbb9bffc0fa2033fe0667c33171da2c0b0581a20150101112131415161718191a1b1c1d1e1f0258407e9e7c96e74ead340967f844a6501da63cdff98013945d8abb930117ecbd1c4218a8db0dc6fce691cb7f0ad7d217cc37e673e1db26e47daeae9b63c49754ac04");
  static final String EXPECTED =
      "a70103025820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0302040105a201010281a20150000102030405060708090a0b0c0d0e0f02a4010103272006215820e17c1ebe48de2b7f7a34cb50662d2ff458a11fa909debf300a70cecda9392f5508a2010002a201010281a20150101112131415161718191a1b1c1d1e1f02a4010103272006215820753fd15f9c77d97898e4385827d759ca52650c8594aa3f9e5051a0a89db31c2b09a10100";

  @Test
  void v304VerifiesAndAppliesExactly() {
    var t = ProtocolV2TransitionVerifier.verifyAndApply(PREV, SIGNED);
    assertEquals(1, t.predecessorSequence());
    assertEquals(2, t.successorSequence());
    assertEquals(EXPECTED, H.formatHex(t.successorStateBytes()));
    assertEquals(
        "12200981d3498020d96bb434d18e10cea3686bf2011034ec72134847a31ba22372bc",
        H.formatHex(t.successorStateHash()));
  }

  @Test
  void tamperedPredecessorRejected() {
    byte[] x = PREV.clone();
    x[x.length - 1] ^= 1;
    assertThrows(
        IllegalArgumentException.class,
        () -> ProtocolV2TransitionVerifier.verifyAndApply(x, SIGNED));
  }

  @Test
  void tamperedControllerSignatureRejected() {
    byte[] x = SIGNED.clone();
    x[x.length - 100] ^= 1;
    assertThrows(
        IllegalArgumentException.class, () -> ProtocolV2TransitionVerifier.verifyAndApply(PREV, x));
  }

  @Test
  void tamperedAuthenticationPopRejected() {
    byte[] x = SIGNED.clone();
    x[x.length - 1] ^= 1;
    assertThrows(
        IllegalArgumentException.class, () -> ProtocolV2TransitionVerifier.verifyAndApply(PREV, x));
  }

  @Test
  void missingAuthenticationPopRejected() {
    byte[] x = removeAuthenticationProofField(SIGNED);
    assertThrows(
        IllegalArgumentException.class, () -> ProtocolV2TransitionVerifier.verifyAndApply(PREV, x));
  }

  @Test
  void duplicateAuthenticationPopRejected() {
    byte[] proof = extractAuthenticationProof(SIGNED);
    byte[] x = replaceAuthenticationProofArray(SIGNED, proof, proof);
    assertThrows(
        IllegalArgumentException.class, () -> ProtocolV2TransitionVerifier.verifyAndApply(PREV, x));
  }

  @Test
  void unauthorizedAuthenticationMethodRejected() {
    byte[] x = SIGNED.clone();
    int method = lastIndexOf(x, H.parseHex("101112131415161718191a1b1c1d1e1f"));
    assertTrue(method > 0);
    x[method] = (byte) 0x20;
    assertThrows(
        IllegalArgumentException.class, () -> ProtocolV2TransitionVerifier.verifyAndApply(PREV, x));
  }

  private static byte[] removeAuthenticationProofField(byte[] in) {
    // V304 envelope is map(3): 1 operation, 2 controller proofs, 5 auth proofs.
    // Re-encode as map(2) using exact encoded values.
    var r = new org.openidentity.cbor.StrictCborReader(in);
    r.readMapHeader();
    r.readUnsigned();
    byte[] op = r.readEncoded();
    r.readUnsigned();
    byte[] cp = r.readEncoded();
    var w = new org.openidentity.cbor.DeterministicCborWriter();
    w.writeMapHeader(2);
    w.writeUnsigned(1);
    w.writeEncoded(op);
    w.writeUnsigned(2);
    w.writeEncoded(cp);
    return w.toByteArray();
  }

  private static byte[] extractAuthenticationProof(byte[] in) {
    var r = new org.openidentity.cbor.StrictCborReader(in);
    r.readMapHeader();
    r.readUnsigned();
    r.skipValue();
    r.readUnsigned();
    r.skipValue();
    r.readUnsigned();
    long n = r.readArrayHeader();
    assertEquals(1, n);
    return r.readEncoded();
  }

  private static byte[] replaceAuthenticationProofArray(byte[] in, byte[]... proofs) {
    var r = new org.openidentity.cbor.StrictCborReader(in);
    r.readMapHeader();
    r.readUnsigned();
    byte[] op = r.readEncoded();
    r.readUnsigned();
    byte[] cp = r.readEncoded();
    r.readUnsigned();
    r.skipValue();
    var w = new org.openidentity.cbor.DeterministicCborWriter();
    w.writeMapHeader(3);
    w.writeUnsigned(1);
    w.writeEncoded(op);
    w.writeUnsigned(2);
    w.writeEncoded(cp);
    w.writeUnsigned(5);
    w.writeArrayHeader(proofs.length);
    for (byte[] p : proofs) w.writeEncoded(p);
    return w.toByteArray();
  }

  private static int lastIndexOf(byte[] a, byte[] needle) {
    outer:
    for (int i = a.length - needle.length; i >= 0; i--) {
      for (int j = 0; j < needle.length; j++) if (a[i + j] != needle[j]) continue outer;
      return i;
    }
    return -1;
  }
}
