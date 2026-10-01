package org.openidentity.auth;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;import org.bouncycastle.crypto.signers.Ed25519Signer;import org.junit.jupiter.api.Test;
import java.security.SecureRandom;import java.util.*;import static org.junit.jupiter.api.Assertions.*;

final class Oi015AdversarialVerificationTest {
 private final byte[] id=new byte[32],state=new byte[34],aud=new byte[32],nonce=new byte[32],context=new byte[34],method={1};
 private final Ed25519PrivateKeyParameters key=new Ed25519PrivateKeyParameters(new SecureRandom());
 private final Oi015Verifier verifier=new Oi015Verifier(x->new CurrentAuthenticationState(id,state,true,new AuthenticationPolicySnapshot(0,1,List.of(new AuthenticationMethod(method,key.generatePublicKey().getEncoded())))),300);
 @Test void mutationsAndExpiryFailClosed(){
  var good=signed(id,state,0,aud,nonce,context,100,200);assertTrue(verifier.tryVerify(good,aud,"openidentity.external-oidc.bind",nonce,context,150).valid());
  byte[] x=aud.clone();x[0]^=1;assertFalse(verifier.tryVerify(good,x,"openidentity.external-oidc.bind",nonce,context,150).valid());
  x=nonce.clone();x[0]^=1;assertFalse(verifier.tryVerify(good,aud,"openidentity.external-oidc.bind",x,context,150).valid());
  x=context.clone();x[2]^=1;var cr=verifier.tryVerify(good,aud,"openidentity.external-oidc.bind",nonce,x,150);assertFalse(cr.valid());assertTrue(cr.contextMismatch());
  assertFalse(verifier.tryVerify(good,aud,"openidentity.external-oidc.bind",nonce,context,200).valid());
  byte[] other=id.clone();other[0]=1;assertFalse(verifier.tryVerify(signed(other,state,0,aud,nonce,context,100,200),aud,"openidentity.external-oidc.bind",nonce,context,150).valid());
  assertFalse(verifier.tryVerify(signed(id,state,1,aud,nonce,context,100,200),aud,"openidentity.external-oidc.bind",nonce,context,150).valid());
 }
 private SecuredAuthenticationAssertion signed(byte[] identity,byte[] sh,long gen,byte[] audience,byte[] n,byte[] ctx,long issued,long expires){
  var base=new AuthenticationAssertion(1,identity,sh,gen,audience,"openidentity.external-oidc.bind",issued,expires,n,ctx,new byte[0]);byte[] exact=Oi015Codec.encodeAssertion(base);var a=new AuthenticationAssertion(1,identity,sh,gen,audience,base.purpose(),issued,expires,n,ctx,exact);
  byte[] in=AuthenticationAssertionCodec.signingBytes(a,method);var s=new Ed25519Signer();s.init(true,key);s.update(in,0,in.length);return new SecuredAuthenticationAssertion(a,List.of(new AuthenticationProof(method,s.generateSignature())));
 }
}