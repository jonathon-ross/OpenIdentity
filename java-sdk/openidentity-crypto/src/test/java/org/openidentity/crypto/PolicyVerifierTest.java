package org.openidentity.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.openidentity.core.ControllerPolicy;
import org.openidentity.core.Ed25519Key;
import org.openidentity.core.VerificationMethod;
import org.openidentity.core.VerificationMethodId;

class PolicyVerifierTest {
  private static final HexFormat HEX = HexFormat.of();

  private static byte[] h(String s) {
    return HEX.parseHex(s);
  }

  private static final byte[] INPUT =
      h(
          "83764f70656e4964656e74697479204f7065726174696f6e015895a601010202035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0402055822122091584ca3a54ebcf93d77c38ea09f68d33c99d6565c7aefab008bd11c09f5efa306a101a201010281a20150202122232425262728292a2b2c2d2e2f02a40101032720062158202543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d");
  private static final VerificationMethodId ID =
      VerificationMethodId.of(h("000102030405060708090a0b0c0d0e0f"));
  private static final VerificationMethod METHOD =
      new VerificationMethod(
          ID, Ed25519Key.of(h("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")));
  private static final byte[] SIG =
      h(
          "cb88120653060470be999a194f766d31c7b11871af89491ef2ad3030e2c1540d570076913cf94ac72eb1ccf450aa83afa2fd9481041daa7af2cc09e9d93abd0e");

  @Test
  void singleAcceptsOneValidAuthorizedProof() {
    assertTrue(
        PolicyVerifier.verify(
            ControllerPolicy.single(METHOD), INPUT, List.of(new SignatureProof(ID, SIG))));
  }

  @Test
  void singleRejectsMissingProof() {
    assertFalse(PolicyVerifier.verify(ControllerPolicy.single(METHOD), INPUT, List.of()));
  }

  @Test
  void duplicateProofIdIsRejectedRatherThanDoubleCounted() {
    SignatureProof p = new SignatureProof(ID, SIG);
    assertFalse(PolicyVerifier.verify(ControllerPolicy.single(METHOD), INPUT, List.of(p, p)));
  }

  @Test
  void unknownProofIdIsRejected() {
    VerificationMethodId other = VerificationMethodId.of(h("101112131415161718191a1b1c1d1e1f"));
    assertFalse(
        PolicyVerifier.verify(
            ControllerPolicy.single(METHOD), INPUT, List.of(new SignatureProof(other, SIG))));
  }

  @Test
  void invalidSignatureDoesNotSatisfyThreshold() {
    byte[] bad = SIG.clone();
    bad[0] ^= 1;
    assertFalse(
        PolicyVerifier.verify(
            ControllerPolicy.single(METHOD), INPUT, List.of(new SignatureProof(ID, bad))));
  }
}
