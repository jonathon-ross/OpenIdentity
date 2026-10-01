package org.openidentity.oidc;

import org.junit.jupiter.api.Test;
import java.util.HexFormat;
import static org.junit.jupiter.api.Assertions.assertEquals;

final class ExternalOidcBindingV1Test {
 private static final HexFormat HEX=HexFormat.of();
 private static final String ID="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
 private static final String BINDING="a80101025820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f03781868747470733a2f2f6964702e6578616d706c652e74657374046b7375626a6563742d3132330578186f70656e6964656e746974792d6c696e6b2d636c69656e74061a6abe130007f60803";
 private static final String BID="1220c3d3e68761cadb4aed0c06ed7fd7c9d1273473d9cdbb714fbf0125d0925dd82e";
 private static final String BCTX="aa01010201035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f04781868747470733a2f2f6964702e6578616d706c652e74657374056b7375626a6563742d3132330678186f70656e6964656e746974792d6c696e6b2d636c69656e74075820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0803091a6abe13000af6";
 private static final String BCH="1220b61b5fef74d75ef0d8ac41995e90c1ca8cb94a3db0544558e672743ebdfcc4ed";
 private static final String RCTX="ab01010202035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f04781868747470733a2f2f6964702e6578616d706c652e74657374056b7375626a6563742d3132330678186f70656e6964656e746974792d6c696e6b2d636c69656e74075820606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f0803091a6abe13000af60b58221220c3d3e68761cadb4aed0c06ed7fd7c9d1273473d9cdbb714fbf0125d0925dd82e";
 private static final String RCH="1220fdef316eff6a631ab891e9de44d7d07d416be2f520aba8afdfa399c616af2423";

 @Test void reproducesIndependentB01AndB03Artifacts(){
  var b=new ExternalOidcBindingV1.Binding(HEX.parseHex(ID),"https://idp.example.test","subject-123","openidentity-link-client",1790841600L,null,3);
  byte[] bb=ExternalOidcBindingV1.encode(b),bid=ExternalOidcBindingV1.bindingId(b);
  byte[] bc=ExternalOidcBindingV1.encodeContext(1,b,HEX.parseHex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"),null);
  byte[] rc=ExternalOidcBindingV1.encodeContext(2,b,HEX.parseHex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"),bid);
  assertEquals(BINDING,HEX.formatHex(bb));assertEquals(BID,HEX.formatHex(bid));
  assertEquals(BCTX,HEX.formatHex(bc));assertEquals(BCH,HEX.formatHex(ExternalOidcBindingV1.contextHash(bc)));
  assertEquals(RCTX,HEX.formatHex(rc));assertEquals(RCH,HEX.formatHex(ExternalOidcBindingV1.contextHash(rc)));
 }
}
