package org.openidentity.delegation;

import org.junit.jupiter.api.Test;
import org.openidentity.cbor.DeterministicCborWriter;
import org.openidentity.crypto.Sha256Multihash;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class FrozenDelegationCompatibilityTest {
 record E(byte[] b){}
 static byte[] h(String s){try{return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));}catch(Exception e){throw new RuntimeException(e);}}
 static byte[] seq(int start,int n){byte[] b=new byte[n];for(int i=0;i<n;i++)b[i]=(byte)(start+i);return b;}
 static void write(DeterministicCborWriter w,Object x){if(x instanceof Integer i)w.writeUnsigned(i);else if(x instanceof Long l)w.writeUnsigned(l);else if(x instanceof byte[] b)w.writeByteString(b);else if(x instanceof E e){for(byte q:e.b())throw new UnsupportedOperationException("encoded helper unavailable");}else throw new IllegalArgumentException();}
 static byte[] map(Object... kv){DeterministicCborWriter w=new DeterministicCborWriter();w.writeMapHeader(kv.length/2);for(int i=0;i<kv.length;i+=2){w.writeUnsigned((Integer)kv[i]);Object x=kv[i+1];if(x instanceof Integer z)w.writeUnsigned(z);else if(x instanceof Long z)w.writeUnsigned(z);else if(x instanceof byte[] b)w.writeByteString(b);else if(x instanceof byte[][] a){w.writeArrayHeader(a.length);for(byte[] b:a)w.writeByteString(b);}else throw new IllegalArgumentException();}return w.toByteArray();}

 @Test void ds01FrozenGrantParsesWithExactCoreFacts(){
  byte[] root=seq(0,32),delegate=seq(32,32),profileHash=Sha256Multihash.digest("OI-016 DS01 capability profile".getBytes(StandardCharsets.UTF_8));
  // Exact deterministic bytes from the frozen DS01 construction, expressed directly as hex to avoid testing production encoder with itself.
  String grantHex="a70101025820"+HexFormat.of().formatHex(root)+"03a20101025820"+HexFormat.of().formatHex(root)+
    "04a20101025820"+HexFormat.of().formatHex(delegate)+"0581a101a201a20101025822"+HexFormat.of().formatHex(profileHash)+
    "024d646f63756d656e742e72656164071a7756b210095820"+HexFormat.of().formatHex(h("OpenIdentity OI-016 DS01 grant nonce"));
  byte[] grant=HexFormat.of().parseHex(grantHex);DelegationGrant g=Oi014Codec.decodeGrant(grant);
  assertArrayEquals(root,g.rootGrantor());assertInstanceOf(OpenIdentityPrincipal.class,g.issuer());assertInstanceOf(OpenIdentityPrincipal.class,g.delegate());
  assertArrayEquals(root,((OpenIdentityPrincipal)g.issuer()).identity());assertArrayEquals(delegate,((OpenIdentityPrincipal)g.delegate()).identity());
  assertNull(g.parentGrantId());assertEquals(1,g.capabilities().size());assertArrayEquals(Sha256Multihash.digest(grant),g.grantId());
 }

 @Test void oi016RejectsMutatedGrantId(){
  byte[] grant=new byte[]{(byte)0xa0};byte[] good=Sha256Multihash.digest(grant),bad=good.clone();bad[33]^=1;
  DeterministicCborWriter w=new DeterministicCborWriter();w.writeMapHeader(3);w.writeUnsigned(1);w.writeUnsigned(1);w.writeUnsigned(2);
  w.writeMapHeader(3);w.writeUnsigned(1);w.writeUnsigned(1);w.writeUnsigned(2);w.writeByteString("r".getBytes(StandardCharsets.UTF_8));w.writeUnsigned(3);w.writeArrayHeader(1);
  w.writeMapHeader(2);w.writeUnsigned(1);w.writeByteString(grant);w.writeUnsigned(2);w.writeByteString(bad);
  w.writeUnsigned(3);w.writeByteString(Sha256Multihash.digest("assertion".getBytes(StandardCharsets.UTF_8)));
  assertThrows(IllegalArgumentException.class,()->Oi016Codec.decode(w.toByteArray()));
 }
}
