package org.openidentity.bootstrap;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.openidentity.cbor.DeterministicCborWriter;
import java.security.*;import java.util.*;

public final class CreateIdentityV2 {
 public record Created(byte[] identity,byte[] stateBytes,byte[] stateHash,byte[] operationBytes,
  byte[] controllerMethodId,byte[] controllerPublicKey,byte[] controllerSeed,byte[] controllerSignature,
  byte[] authenticationMethodId,byte[] authenticationPublicKey,byte[] authenticationSeed,byte[] authenticationPop){
  public Created{identity=identity.clone();stateBytes=stateBytes.clone();stateHash=stateHash.clone();operationBytes=operationBytes.clone();controllerMethodId=controllerMethodId.clone();controllerPublicKey=controllerPublicKey.clone();controllerSeed=controllerSeed.clone();controllerSignature=controllerSignature.clone();authenticationMethodId=authenticationMethodId.clone();authenticationPublicKey=authenticationPublicKey.clone();authenticationSeed=authenticationSeed.clone();authenticationPop=authenticationPop.clone();}
 }
 private CreateIdentityV2(){}
 public static Created create(SecureRandom random){
  byte[] id=new byte[32],cm=new byte[16],am=new byte[16],cs=new byte[32],as=new byte[32];random.nextBytes(id);random.nextBytes(cm);random.nextBytes(am);random.nextBytes(cs);random.nextBytes(as);
  var ck=new Ed25519PrivateKeyParameters(cs,0);var ak=new Ed25519PrivateKeyParameters(as,0);byte[] cp=ck.generatePublicKey().getEncoded(),ap=ak.generatePublicKey().getEncoded();
  byte[] op=operation(id,cm,cp,am,ap);byte[] controller=sign(ck,operationSigning(op));byte[] auth=sign(ak,authenticationPopSigning(op,am));byte[] state=state(id,cm,cp,am,ap);
  return new Created(id,state,CreateIdentityV01.stateHash(state),op,cm,cp,cs,controller,am,ap,as,auth);
 }
 public static byte[] operation(byte[] id,byte[] cm,byte[] cp,byte[] am,byte[] ap){
  var w=new DeterministicCborWriter();w.writeMapHeader(6);u(w,1);u(w,2);u(w,2);u(w,1);u(w,3);w.writeByteString(id);u(w,4);u(w,1);u(w,5);w.writeNull();u(w,6);w.writeMapHeader(2);u(w,1);policy(w,cm,cp);u(w,4);policy(w,am,ap);return w.toByteArray();
 }
 public static byte[] state(byte[] id,byte[] cm,byte[] cp,byte[] am,byte[] ap){
  var w=new DeterministicCborWriter();w.writeMapHeader(7);u(w,1);u(w,3);u(w,2);w.writeByteString(id);u(w,3);u(w,1);u(w,4);u(w,1);u(w,5);policy(w,cm,cp);u(w,8);w.writeMapHeader(2);u(w,1);u(w,0);u(w,2);policy(w,am,ap);u(w,9);w.writeMapHeader(1);u(w,1);u(w,0);return w.toByteArray();
 }
 public static byte[] operationSigning(byte[] op){var w=new DeterministicCborWriter();w.writeArrayHeader(3);w.writeTextString("OpenIdentity Operation");u(w,1);w.writeByteString(op);return w.toByteArray();}
 public static byte[] authenticationPopSigning(byte[] op,byte[] method){var w=new DeterministicCborWriter();w.writeArrayHeader(4);w.writeTextString("OpenIdentity Authentication Proof");u(w,1);w.writeByteString(op);w.writeByteString(method);return w.toByteArray();}
 private static byte[] sign(Ed25519PrivateKeyParameters k,byte[] in){Ed25519Signer s=new Ed25519Signer();s.init(true,k);s.update(in,0,in.length);return s.generateSignature();}
 private static void policy(DeterministicCborWriter w,byte[] id,byte[] pk){w.writeMapHeader(2);u(w,1);u(w,1);u(w,2);w.writeArrayHeader(1);w.writeMapHeader(2);u(w,1);w.writeByteString(id);u(w,2);cose(w,pk);}
 private static void cose(DeterministicCborWriter w,byte[] pk){w.writeMapHeader(4);u(w,1);u(w,1);u(w,3);w.writeNegative(-8);w.writeNegative(-1);u(w,6);w.writeNegative(-2);w.writeByteString(pk);}
 private static void u(DeterministicCborWriter w,long n){w.writeUnsigned(n);}
}
