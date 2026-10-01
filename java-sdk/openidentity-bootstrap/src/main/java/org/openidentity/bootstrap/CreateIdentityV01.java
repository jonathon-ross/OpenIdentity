package org.openidentity.bootstrap;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.openidentity.cbor.DeterministicCborWriter;
import org.openidentity.core.*;
import java.security.*;import java.util.*;

public final class CreateIdentityV01 {
 public record Created(byte[] identity,byte[] stateBytes,byte[] stateHash,byte[] operationBytes,byte[] methodId,byte[] publicKey,byte[] privateSeed,byte[] signature){
  public Created{identity=identity.clone();stateBytes=stateBytes.clone();stateHash=stateHash.clone();operationBytes=operationBytes.clone();methodId=methodId.clone();publicKey=publicKey.clone();privateSeed=privateSeed.clone();signature=signature.clone();}
 }
 private CreateIdentityV01(){}
 public static Created create(SecureRandom random){
  byte[] identity=new byte[32],methodId=new byte[16],seed=new byte[32];random.nextBytes(identity);random.nextBytes(methodId);random.nextBytes(seed);
  var priv=new Ed25519PrivateKeyParameters(seed,0);byte[] pub=priv.generatePublicKey().getEncoded();
  byte[] op=operation(identity,methodId,pub),signing=operationSigningBytes(op);Ed25519Signer signer=new Ed25519Signer();signer.init(true,priv);signer.update(signing,0,signing.length);byte[] sig=signer.generateSignature();
  byte[] state=state(identity,methodId,pub),hash=stateHash(state);return new Created(identity,state,hash,op,methodId,pub,seed,sig);
 }
 public static byte[] operation(byte[] identity,byte[] methodId,byte[] publicKey){
  check(identity,32,"identity");check(methodId,16,"methodId");check(publicKey,32,"publicKey");var w=new DeterministicCborWriter();w.writeMapHeader(6);
  u(w,1);u(w,1);u(w,2);u(w,1);u(w,3);w.writeByteString(identity);u(w,4);u(w,1);u(w,5);w.writeNull();u(w,6);w.writeMapHeader(1);u(w,1);singlePolicy(w,methodId,publicKey);return w.toByteArray();
 }
 public static byte[] state(byte[] identity,byte[] methodId,byte[] publicKey){
  check(identity,32,"identity");check(methodId,16,"methodId");check(publicKey,32,"publicKey");var w=new DeterministicCborWriter();w.writeMapHeader(5);
  u(w,1);u(w,1);u(w,2);w.writeByteString(identity);u(w,3);u(w,1);u(w,4);u(w,1);u(w,5);singlePolicy(w,methodId,publicKey);return w.toByteArray();
 }
 public static byte[] operationSigningBytes(byte[] op){var w=new DeterministicCborWriter();w.writeArrayHeader(3);w.writeTextString("OpenIdentity Operation");u(w,1);w.writeByteString(op);return w.toByteArray();}
 public static byte[] stateHash(byte[] state){try{byte[] d=MessageDigest.getInstance("SHA-256").digest(state),out=new byte[34];out[0]=0x12;out[1]=0x20;System.arraycopy(d,0,out,2,32);return out;}catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}}
 private static void singlePolicy(DeterministicCborWriter w,byte[] id,byte[] pk){w.writeMapHeader(2);u(w,1);u(w,1);u(w,2);w.writeArrayHeader(1);w.writeMapHeader(2);u(w,1);w.writeByteString(id);u(w,2);ed25519(w,pk);}
 private static void ed25519(DeterministicCborWriter w,byte[] pk){w.writeMapHeader(4);w.writeNegative(-2);w.writeByteString(pk);w.writeNegative(-1);u(w,6);u(w,1);u(w,1);u(w,3);w.writeNegative(-8);}
 private static void u(DeterministicCborWriter w,long n){w.writeUnsigned(n);}private static void check(byte[] b,int n,String x){if(b==null||b.length!=n)throw new IllegalArgumentException(x);}
}
