package org.openidentity.auth;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.Test;
import org.openidentity.crypto.Sha256Multihash;
import org.openidentity.core.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class Oi015VerifierTest {
 static byte[] h(String s){try{return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));}catch(Exception e){throw new RuntimeException(e);}}
 static byte[] sign(Ed25519PrivateKeyParameters key,byte[] msg){Ed25519Signer s=new Ed25519Signer();s.init(true,key);s.update(msg,0,msg.length);return s.generateSignature();}
 static AuthenticationAssertion assertion(byte[] identity,byte[] stateHash,long gen,byte[] audience,byte[] nonce,byte[] context,long issued,long expires){
  // Exact bytes are an opaque frozen parser output to the verifier; AssertionId hashes these exact bytes.
  byte[] exact=("fixture-"+gen+"-"+issued+"-"+expires).getBytes(StandardCharsets.UTF_8);
  return new AuthenticationAssertion(1,identity,stateHash,gen,audience,"openidentity.oauth.token-exchange",issued,expires,nonce,context,exact);
 }
 @Test void verifiesCurrentPolicyAndExactContext(){
  byte[] identity=h("identity"),stateHash=Sha256Multihash.digest(h("state")),mid=Arrays.copyOf(h("method"),16);
  Ed25519PrivateKeyParameters key=new Ed25519PrivateKeyParameters(h("auth-key"),0);
  var method=new AuthenticationMethod(mid,key.generatePublicKey().getEncoded());var policy=new AuthenticationPolicySnapshot(7,1,List.of(method));
  AuthenticationStateResolver resolver=id->new CurrentAuthenticationState(identity,stateHash,true,policy);
  byte[] aud="https://as.example.test".getBytes(StandardCharsets.UTF_8),nonce=h("nonce"),ctx=Sha256Multihash.digest(h("context"));
  var a=assertion(identity,stateHash,7,aud,nonce,ctx,1000,1240);
  byte[] sig=sign(key,AuthenticationAssertionCodec.signingBytes(a,mid));
  var secured=new SecuredAuthenticationAssertion(a,List.of(new AuthenticationProof(mid,sig)));
  var out=new Oi015Verifier(resolver,300).verify(secured,aud,"openidentity.oauth.token-exchange",nonce,ctx,1100);
  assertArrayEquals(identity,out.identity());assertArrayEquals(Sha256Multihash.digest(a.exactAssertionBytes()),out.assertionId());
 }
 @Test void rejectsContextSubstitution(){
  byte[] identity=h("identity2"),stateHash=Sha256Multihash.digest(h("state2")),mid=Arrays.copyOf(h("method2"),16);
  Ed25519PrivateKeyParameters key=new Ed25519PrivateKeyParameters(h("auth-key2"),0);
  var policy=new AuthenticationPolicySnapshot(9,1,List.of(new AuthenticationMethod(mid,key.generatePublicKey().getEncoded())));
  byte[] aud="as".getBytes(StandardCharsets.UTF_8),nonce=h("n2"),ctx=Sha256Multihash.digest(h("ctx2"));
  var a=assertion(identity,stateHash,9,aud,nonce,ctx,2000,2240);var secured=new SecuredAuthenticationAssertion(a,List.of(new AuthenticationProof(mid,sign(key,AuthenticationAssertionCodec.signingBytes(a,mid)))));
  var v=new Oi015Verifier(id->new CurrentAuthenticationState(identity,stateHash,true,policy),300);
  VerificationException e=assertThrows(VerificationException.class,()->v.verify(secured,aud,"openidentity.oauth.token-exchange",nonce,Sha256Multihash.digest(h("other")),2100));
  assertEquals(VerificationError.ASSERTION_CONTEXT_BINDING_MISMATCH,e.error());
 }
 @Test void rejectsStaleGeneration(){
  byte[] identity=h("identity3"),stateHash=Sha256Multihash.digest(h("state3")),mid=Arrays.copyOf(h("method3"),16);
  Ed25519PrivateKeyParameters key=new Ed25519PrivateKeyParameters(h("auth-key3"),0);
  var policy=new AuthenticationPolicySnapshot(11,1,List.of(new AuthenticationMethod(mid,key.generatePublicKey().getEncoded())));
  byte[] aud="as".getBytes(StandardCharsets.UTF_8),nonce=h("n3"),ctx=Sha256Multihash.digest(h("ctx3"));
  var a=assertion(identity,stateHash,10,aud,nonce,ctx,3000,3240);var secured=new SecuredAuthenticationAssertion(a,List.of(new AuthenticationProof(mid,sign(key,AuthenticationAssertionCodec.signingBytes(a,mid)))));
  VerificationException e=assertThrows(VerificationException.class,()->new Oi015Verifier(id->new CurrentAuthenticationState(identity,stateHash,true,policy),300).verify(secured,aud,"openidentity.oauth.token-exchange",nonce,ctx,3100));
  assertEquals(VerificationError.INVALID_INPUT,e.error());
 }
}
