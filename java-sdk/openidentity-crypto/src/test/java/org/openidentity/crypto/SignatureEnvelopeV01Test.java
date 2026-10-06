package org.openidentity.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.openidentity.core.Ed25519Key;
import org.openidentity.core.VerificationMethodId;

class SignatureEnvelopeV01Test {
  private static final HexFormat HEX = HexFormat.of();

  private static byte[] h(String s) {
    return HEX.parseHex(s);
  }

  @Test
  void se01OrdinaryAuthorizationMatchesFrozenSigningInputAndVerifies() {
    byte[] operation =
        h(
            "a601010202035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0402055822122091584ca3a54ebcf93d77c38ea09f68d33c99d6565c7aefab008bd11c09f5efa306a101a201010281a20150202122232425262728292a2b2c2d2e2f02a40101032720062158202543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d");
    byte[] expected =
        h(
            "83764f70656e4964656e74697479204f7065726174696f6e015895a601010202035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0402055822122091584ca3a54ebcf93d77c38ea09f68d33c99d6565c7aefab008bd11c09f5efa306a101a201010281a20150202122232425262728292a2b2c2d2e2f02a40101032720062158202543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d");
    byte[] signature =
        h(
            "cb88120653060470be999a194f766d31c7b11871af89491ef2ad3030e2c1540d570076913cf94ac72eb1ccf450aa83afa2fd9481041daa7af2cc09e9d93abd0e");
    assertArrayEquals(expected, SigningInputs.operation(operation));
    assertTrue(
        Ed25519.verify(
            Ed25519Key.of(h("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")),
            expected,
            signature));
  }

  @Test
  void se01ControllerProofInputMatchesFrozenVector() {
    byte[] operation =
        h(
            "a601010202035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0402055822122091584ca3a54ebcf93d77c38ea09f68d33c99d6565c7aefab008bd11c09f5efa306a101a201010281a20150202122232425262728292a2b2c2d2e2f02a40101032720062158202543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d");
    VerificationMethodId id = VerificationMethodId.of(h("202122232425262728292a2b2c2d2e2f"));
    byte[] expected =
        h(
            "84781d4f70656e4964656e7469747920436f6e74726f6c6c65722050726f6f66015895a601010202035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0402055822122091584ca3a54ebcf93d77c38ea09f68d33c99d6565c7aefab008bd11c09f5efa306a101a201010281a20150202122232425262728292a2b2c2d2e2f02a40101032720062158202543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d50202122232425262728292a2b2c2d2e2f");
    assertArrayEquals(expected, SigningInputs.controllerProof(operation, id));
  }

  @Test
  void se01AuthorizationProofMatchesFrozenVector() {
    SignatureProof proof =
        new SignatureProof(
            VerificationMethodId.of(h("000102030405060708090a0b0c0d0e0f")),
            h(
                "cb88120653060470be999a194f766d31c7b11871af89491ef2ad3030e2c1540d570076913cf94ac72eb1ccf450aa83afa2fd9481041daa7af2cc09e9d93abd0e"));
    assertArrayEquals(
        h(
            "a20150000102030405060708090a0b0c0d0e0f025840cb88120653060470be999a194f766d31c7b11871af89491ef2ad3030e2c1540d570076913cf94ac72eb1ccf450aa83afa2fd9481041daa7af2cc09e9d93abd0e"),
        proof.encode());
  }

  @Test
  void domainsAreCryptographicallySeparated() {
    byte[] operation =
        h(
            "a601010202035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0402055822122091584ca3a54ebcf93d77c38ea09f68d33c99d6565c7aefab008bd11c09f5efa306a101a201010281a20150202122232425262728292a2b2c2d2e2f02a40101032720062158202543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d");
    VerificationMethodId id = VerificationMethodId.of(h("000102030405060708090a0b0c0d0e0f"));
    assertFalse(
        java.util.Arrays.equals(
            SigningInputs.operation(operation), SigningInputs.recovery(operation, id)));
    assertFalse(
        java.util.Arrays.equals(
            SigningInputs.operation(operation), SigningInputs.controllerProof(operation, id)));
  }
}
