package org.openidentity.operations;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.openidentity.core.*;

class CreateOperationTest {
  private static final HexFormat H = HexFormat.of();

  private static byte[] h(String s) {
    return H.parseHex(s);
  }

  @Test
  void v01SingleEd25519CreateMatchesFrozenOperationBytes() {
    IdentityId identity =
        IdentityId.of(h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    VerificationMethod method =
        new VerificationMethod(
            VerificationMethodId.of(h("000102030405060708090a0b0c0d0e0f")),
            Ed25519Key.of(h("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")));
    CreateOperation op = new CreateOperation(identity, ControllerPolicy.single(method), null);
    assertEquals(1, op.protocolVersion());
    assertEquals(OperationType.CREATE, op.operationType());
    assertArrayEquals(
        h(
            "a601010201035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f040105f606a101a201010281a20150000102030405060708090a0b0c0d0e0f02a401010327200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"),
        op.encode());
  }
}
