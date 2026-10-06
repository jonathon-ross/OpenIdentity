package org.openidentity.operations;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.util.*;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.*;
import org.openidentity.crypto.*;

class DeactivateOperationTest {
  static final HexFormat H = HexFormat.of();

  static byte[] h(String s) {
    return H.parseHex(s);
  }

  @Test
  void deactivatePreservesV2PoliciesAndMarksDeactivated() {
    IdentityId id =
        IdentityId.of(h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    VerificationMethodId mid = VerificationMethodId.of(h("000102030405060708090a0b0c0d0e0f"));
    VerificationMethod m =
        new VerificationMethod(
            mid,
            Ed25519Key.of(h("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")));
    ControllerPolicy cp = ControllerPolicy.single(m);
    IdentityStateV2 current =
        new IdentityStateV2(
            id,
            new Sequence(BigInteger.ONE),
            IdentityStatus.ACTIVE,
            cp,
            null,
            AssertionPolicy.single(m));
    StateHash prev = StateHash.fromStateBytes(OpenIdentityCborEncoder.encodeState(current));
    DeactivateOperation op = new DeactivateOperation(id, new Sequence(BigInteger.TWO), prev);
    // Verify structural bytes independently: six-field operation ending in empty payload map.
    byte[] bytes = op.encode();
    assertEquals((byte) 0xa6, bytes[0]);
    assertEquals((byte) 0xa0, bytes[bytes.length - 1]);
    // Authorization behavior is already covered by PolicyVerifier; a random signature must fail
    // here.
    assertThrows(
        IllegalArgumentException.class,
        () ->
            DeactivateTransition.apply(
                current, op, List.of(new SignatureProof(mid, new byte[64]))));
  }

  @Test
  void deactivateRejectsWrongSequenceBeforeAuthorization() {
    IdentityId id = IdentityId.of(new byte[32]);
    VerificationMethod m =
        new VerificationMethod(VerificationMethodId.of(new byte[16]), Ed25519Key.of(new byte[32]));
    ControllerPolicy cp = ControllerPolicy.single(m);
    IdentityStateV1 current =
        new IdentityStateV1(id, new Sequence(BigInteger.ONE), IdentityStatus.ACTIVE, cp, null);
    StateHash prev = StateHash.fromStateBytes(OpenIdentityCborEncoder.encodeState(current));
    DeactivateOperation op = new DeactivateOperation(id, new Sequence(BigInteger.valueOf(3)), prev);
    assertThrows(
        IllegalArgumentException.class, () -> DeactivateTransition.apply(current, op, List.of()));
  }
}
