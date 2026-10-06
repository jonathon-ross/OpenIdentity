package org.openidentity.cbor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.openidentity.core.*;

class V01EncodingTest {
  private static byte[] hex(String v) {
    return HexFormat.of().parseHex(v);
  }

  @Test
  void matchesPublishedV01MethodAndPolicy() {
    VerificationMethod method =
        new VerificationMethod(
            VerificationMethodId.of(hex("000102030405060708090a0b0c0d0e0f")),
            Ed25519Key.of(hex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")));
    assertArrayEquals(
        hex(
            "a20150000102030405060708090a0b0c0d0e0f02a401010327200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"),
        OpenIdentityCborEncoder.encodeVerificationMethod(method));
    assertArrayEquals(
        hex(
            "a201010281a20150000102030405060708090a0b0c0d0e0f02a401010327200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"),
        OpenIdentityCborEncoder.encodeControllerPolicy(ControllerPolicy.single(method)));
  }
}
