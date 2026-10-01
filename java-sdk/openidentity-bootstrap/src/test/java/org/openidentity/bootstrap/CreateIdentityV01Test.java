package org.openidentity.bootstrap;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.Test;
import java.security.*;import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class CreateIdentityV01Test {
 @Test void frozenV01ShapeStateHashAndAuthorizationSignatureAreSelfConsistent() throws Exception {
  byte[] id=new byte[32],mid=new byte[16],seed=new byte[32];for(int i=0;i<id.length;i++)id[i]=(byte)i;for(int i=0;i<mid.length;i++)mid[i]=(byte)(0x10+i);Arrays.fill(seed,(byte)7);
  var priv=new org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(seed,0);byte[] pub=priv.generatePublicKey().getEncoded();
  byte[] op=CreateIdentityV01.operation(id,mid,pub),state=CreateIdentityV01.state(id,mid,pub),hash=CreateIdentityV01.stateHash(state);
  assertEquals("a601010201035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f040105f606a101a201010281a20150101112131415161718191a1b1c1d1e1f02a4010103272006215820",HexFormat.of().formatHex(op).substring(0,160));
  assertEquals("a50101025820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0301040105a201010281a20150101112131415161718191a1b1c1d1e1f02a4010103272006215820",HexFormat.of().formatHex(state).substring(0,152));
  assertEquals(34,hash.length);assertEquals(0x12,hash[0]&255);assertEquals(0x20,hash[1]&255);assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(state),Arrays.copyOfRange(hash,2,34));
  byte[] signing=CreateIdentityV01.operationSigningBytes(op);Ed25519Signer s=new Ed25519Signer();s.init(true,priv);s.update(signing,0,signing.length);byte[] sig=s.generateSignature();Ed25519Signer v=new Ed25519Signer();v.init(false,new Ed25519PublicKeyParameters(pub,0));v.update(signing,0,signing.length);assertTrue(v.verifySignature(sig));
 }
 @Test void createGeneratesIndependentIdentityMethodAndKeyMaterial(){
  var c=CreateIdentityV01.create(new SecureRandom());assertEquals(32,c.identity().length);assertEquals(16,c.methodId().length);assertEquals(32,c.publicKey().length);assertEquals(32,c.privateSeed().length);assertEquals(64,c.signature().length);assertEquals(34,c.stateHash().length);
 }
}
