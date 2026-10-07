package org.openidentity.protocol.v2;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;

final class ProtocolV2CreateVerifierTest {
  static final HexFormat H = HexFormat.of();
  static final String V301_SIGNED =
      "a201a601020201035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f040105f606a101a201010281a20150000102030405060708090a0b0c0d0e0f02a40101032720062158203247ef404c59b60bf74076bd1205020a47098a74e60064d65805c644dd9466300281a20150000102030405060708090a0b0c0d0e0f025840d80ba14550fee120429f41ee9fc3d0586a79b095ef345cd2f892c6a42a9a716c2e6c2bc74038e8bd5e31b1fcfe259b9201d5ddf6cec0a84d884e924e5d40530a";
  static final String V301_STATE =
      "a70103025820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0301040105a201010281a20150000102030405060708090a0b0c0d0e0f02a40101032720062158203247ef404c59b60bf74076bd1205020a47098a74e60064d65805c644dd94663008a1010009a10100";
  static final String V301_HASH =
      "1220f6607eec6e20f705e9ca8015d16eafb1717ac75a656e1ae607488a5986cd0e4b";
  static final String V302_SIGNED =
      "a301a601020201035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f040105f606a201a201010281a20150000102030405060708090a0b0c0d0e0f02a4010103272006215820e49416553d2d39c7c4bcf3b73666d65dac93914f0d3408d93d8b929b7f9491a104a201010281a20150101112131415161718191a1b1c1d1e1f02a4010103272006215820aef7e96c04b8cc6f6e648c6c2ad20e8630a3a2406399c7cce8690271dee72ad80281a20150000102030405060708090a0b0c0d0e0f025840d56de3a45887e5a860393f18e8d9b20884d5ebf08436e1f85a81f9a9854b0bb86a151bc9e275387f5fbafb635cbb8edc74b313dae79edeceb58e0c9c7fce6a000581a20150101112131415161718191a1b1c1d1e1f0258407caf70e91fa0d464affa8b81402b669486b42bcf8915ceaaaf44652066349367c353257870238f394d33c14b1dc97f2f02fd8fa8b95fc91146e0edf440eaa007";
  static final String V302_STATE =
      "a70103025820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0301040105a201010281a20150000102030405060708090a0b0c0d0e0f02a4010103272006215820e49416553d2d39c7c4bcf3b73666d65dac93914f0d3408d93d8b929b7f9491a108a2010002a201010281a20150101112131415161718191a1b1c1d1e1f02a4010103272006215820aef7e96c04b8cc6f6e648c6c2ad20e8630a3a2406399c7cce8690271dee72ad809a10100";
  static final String V302_HASH =
      "1220f5ce1c600acdc4c53d0fc2c71a3a24b75ab48950a0d6c266bb890151eb14100c";
  static final String V303_SIGNED =
      "a501a601020201035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f040105f606a401a201010281a20150000102030405060708090a0b0c0d0e0f02a401010327200621582097dfbcd7adc5834c4b0b7717bbaa2e19caa90145633a045c7684326a333e710903a201010281a20150202122232425262728292a2b2c2d2e2f02a4010103272006215820f7f68797d34bfb788af6a947dc51a73d8cd890a0810aabddd2b2f6aa1c44419b04a201010281a20150101112131415161718191a1b1c1d1e1f02a40101032720062158208a0dc124d40a8889dd6247c3de41479163f076bace442f28f491ac1da3bc138b05a201010281a20150303132333435363738393a3b3c3d3e3f02a40101032720062158202e4273ad77c12978887a0e7e5833f78e74c3ad3f76cab260fdccef4030e26b180281a20150000102030405060708090a0b0c0d0e0f0258408a165c9bcf184035e387b4ae7f942ee5a712ebea2b0cd2fb166bf13f45dc6c4cf39fbc6c2d318e61b32d22d051c0047e0e4b21f3beb5cc993c139aa8131f710d0581a20150101112131415161718191a1b1c1d1e1f025840c2bd16e9373fe00213883dca895c76436ddb3c7f8cb223e5969ecd97b463b6237d3f8bb36bd7f328ab24f8dd9935d30ae786d8b59a54b03d541fcbdda02630090681a20150202122232425262728292a2b2c2d2e2f02584024f428fce995252c891dd47538c77c5d170663e8c92504056925a568ef6918a0e94d793a2f95bce7cf31efa3d1976101af2be555c8d490a862280534a9b3dd040781a20150303132333435363738393a3b3c3d3e3f025840baa83c109ef3c614e87ced1b73929f1607cb0f50c874b62fb94739c76c23eb3ea75cdc0d36350ad2591b0381502349a77d39d9cf14dcefcddee28b3f6b3abd03";
  static final String V303_STATE =
      "a80103025820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0301040105a201010281a20150000102030405060708090a0b0c0d0e0f02a401010327200621582097dfbcd7adc5834c4b0b7717bbaa2e19caa90145633a045c7684326a333e710907a201010281a20150202122232425262728292a2b2c2d2e2f02a4010103272006215820f7f68797d34bfb788af6a947dc51a73d8cd890a0810aabddd2b2f6aa1c44419b08a2010002a201010281a20150101112131415161718191a1b1c1d1e1f02a40101032720062158208a0dc124d40a8889dd6247c3de41479163f076bace442f28f491ac1da3bc138b09a2010002a201010281a20150303132333435363738393a3b3c3d3e3f02a40101032720062158202e4273ad77c12978887a0e7e5833f78e74c3ad3f76cab260fdccef4030e26b18";
  static final String V303_HASH =
      "12209f9c41dca905e0e3959f1315ee6fc12849245f3a27fc1c87660423982d52d5cc";

  @Test
  void v301MinimalCreate() {
    check(V301_SIGNED, V301_STATE, V301_HASH);
  }

  @Test
  void v302AuthenticationCreate() {
    check(V302_SIGNED, V302_STATE, V302_HASH);
  }

  @Test
  void v303RichCreate() {
    check(V303_SIGNED, V303_STATE, V303_HASH);
  }

  @Test
  void createRejectsRedundantControllerPop() {
    var r = new org.openidentity.cbor.StrictCborReader(H.parseHex(V301_SIGNED));
    r.readMapHeader();
    r.readUnsigned();
    byte[] op = r.readEncoded();
    r.readUnsigned();
    byte[] auth = r.readEncoded();
    var p = new org.openidentity.cbor.StrictCborReader(auth);
    p.readArrayHeader();
    byte[] proof = p.readEncoded();
    var w = new org.openidentity.cbor.DeterministicCborWriter();
    w.writeMapHeader(3);
    w.writeUnsigned(1);
    w.writeEncoded(op);
    w.writeUnsigned(2);
    w.writeEncoded(auth);
    w.writeUnsigned(3);
    w.writeArrayHeader(1);
    w.writeEncoded(proof);
    assertThrows(
        IllegalArgumentException.class,
        () -> ProtocolV2TransitionVerifier.verifyCreate(w.toByteArray()));
  }

  @Test
  void createRejectsTamperedAuthenticationPop() {
    byte[] x = H.parseHex(V302_SIGNED);
    x[x.length - 1] ^= 1;
    assertThrows(
        IllegalArgumentException.class, () -> ProtocolV2TransitionVerifier.verifyCreate(x));
  }

  @Test
  void createRejectsTamperedAssertionPop() {
    byte[] x = H.parseHex(V303_SIGNED);
    int i = findProofField(x, (byte) 6);
    x[i] ^= 1;
    assertThrows(
        IllegalArgumentException.class, () -> ProtocolV2TransitionVerifier.verifyCreate(x));
  }

  @Test
  void createRejectsTamperedDelegationPop() {
    byte[] x = H.parseHex(V303_SIGNED);
    x[x.length - 1] ^= 1;
    assertThrows(
        IllegalArgumentException.class, () -> ProtocolV2TransitionVerifier.verifyCreate(x));
  }

  private static void check(String signed, String state, String hash) {
    var c = ProtocolV2TransitionVerifier.verifyCreate(H.parseHex(signed));
    assertEquals(1, c.sequence());
    assertEquals(3, c.stateVersion());
    assertEquals(state, H.formatHex(c.stateBytes()));
    assertEquals(hash, H.formatHex(c.stateHash()));
  }

  private static int findProofField(byte[] x, byte field) {
    for (int i = 0; i < x.length - 2; i++)
      if ((x[i] & 255) == field && (x[i + 1] & 255) == 0x81) return x.length - 40;
    return x.length - 40;
  }
}
