package org.openidentity.spring.oidc;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.Test;
import org.openidentity.auth.*;
import org.openidentity.cbor.DeterministicCborWriter;
import org.openidentity.oidc.*;
import java.security.SecureRandom;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.openidentity.oidc.ExternalOidcBindingError.*;

final class ExternalOidcBindingCeremonyTest {
 private static final byte[] ID=HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
 private static final byte[] STATE=new byte[34],AUD="spring-oidc-link".getBytes(java.nio.charset.StandardCharsets.UTF_8),NONCE=new byte[32],METHOD={1};
 private final Ed25519PrivateKeyParameters key=new Ed25519PrivateKeyParameters(new SecureRandom());
 private long generation=3;
 private final AuthenticationPolicySnapshot authPolicy=new AuthenticationPolicySnapshot(3,1,List.of(new AuthenticationMethod(METHOD,key.generatePublicKey().getEncoded())));
 private final Oi015Verifier verifier=new Oi015Verifier(identity->new CurrentAuthenticationState(ID,STATE,true,new AuthenticationPolicySnapshot(generation,1,authPolicy.methods())),300);
 private final InMemoryExternalOidcBindingRegistry.Policy policy=new InMemoryExternalOidcBindingRegistry.Policy(){
  public boolean providerTrusted(String issuer){return true;}public boolean clientAllowed(String issuer,String clientId){return true;}
  public boolean identityActive(byte[] identity){return true;}public long currentAuthenticationGeneration(byte[] identity){return generation;}
  public boolean assuranceSufficient(VerifiedExternalOidcPrincipal p){return true;}
 };
 private static VerifiedExternalOidcPrincipal p(String sub){return new VerifiedExternalOidcPrincipal("https://idp.example.test",sub,"client-1",1790841600L,"urn:acr:test",List.of("pwd"),Map.of());}
 private ExternalOidcBindingCeremony ceremony(InMemoryExternalOidcBindingRegistry r){return new ExternalOidcBindingCeremony(verifier,r,policy,new SecureRandom(new byte[]{1,2,3,4}));}

 @Test void validRealOi015CompletesBinding(){
  var r=new InMemoryExternalOidcBindingRegistry();var c=ceremony(r);var pending=c.begin(p("subject-a"),ID,1790841600L,null);
  var state=c.complete(pending,assertion(pending.contextHash(),ExternalOidcBindingCeremony.BIND_PURPOSE,NONCE,3),AUD,NONCE,1790841610L);
  assertEquals(InMemoryExternalOidcBindingRegistry.Status.ACTIVE,state.status());
  assertArrayEquals(ID,r.resolve(p("subject-a"),1790841620L,policy).identity());
 }
 @Test void accountAWithAuthorizationForAccountBIsRejected(){
  var r=new InMemoryExternalOidcBindingRegistry();var c=ceremony(r);
  var a=c.begin(p("subject-a"),ID,1790841600L,null),b=c.begin(p("subject-b"),ID,1790841600L,null);
  error(BINDING_CONTEXT_MISMATCH,()->c.complete(a,assertion(b.contextHash(),ExternalOidcBindingCeremony.BIND_PURPOSE,NONCE,3),AUD,NONCE,1790841610L));
  error(BINDING_NOT_FOUND,()->r.resolve(p("subject-a"),1790841620L,policy));
 }
 @Test void wrongPurposeAndNonceAreRejected(){
  var r=new InMemoryExternalOidcBindingRegistry();var c=ceremony(r);var p=c.begin(p("subject-a"),ID,1790841600L,null);
  error(BINDING_AUTHORIZATION_INVALID,()->c.complete(p,assertion(p.contextHash(),"openidentity.external-oidc.revoke",NONCE,3),AUD,NONCE,1790841610L));
  byte[] other=new byte[32];other[0]=9;error(BINDING_AUTHORIZATION_INVALID,()->c.complete(p,assertion(p.contextHash(),ExternalOidcBindingCeremony.BIND_PURPOSE,other,3),AUD,NONCE,1790841610L));
 }
 @Test void generationResetBetweenBeginAndCompleteIsRejected(){
  var r=new InMemoryExternalOidcBindingRegistry();var c=ceremony(r);var p=c.begin(p("subject-a"),ID,1790841600L,null);
  var signed=assertion(p.contextHash(),ExternalOidcBindingCeremony.BIND_PURPOSE,NONCE,3);generation=4;
  error(BINDING_AUTHORIZATION_INVALID,()->c.complete(p,signed,AUD,NONCE,1790841610L));
 }
 @Test void completedCeremonyCannotBeReused(){
  var r=new InMemoryExternalOidcBindingRegistry();var c=ceremony(r);var p=c.begin(p("subject-a"),ID,1790841600L,null);
  var signed=assertion(p.contextHash(),ExternalOidcBindingCeremony.BIND_PURPOSE,NONCE,3);
  c.complete(p,signed,AUD,NONCE,1790841610L);
  error(BINDING_CHALLENGE_INVALID,()->c.complete(p,signed,AUD,NONCE,1790841611L));
 }

 private SecuredAuthenticationAssertion assertion(byte[] context,String purpose,byte[] nonce,long gen){
  long issued=1790841600L,expires=1790841660L;
  var w=new DeterministicCborWriter();w.writeMapHeader(10);
  u(w,1);u(w,1);u(w,2);w.writeByteString(ID);u(w,3);w.writeByteString(STATE);u(w,4);u(w,gen);
  u(w,5);w.writeByteString(AUD);u(w,6);w.writeTextString(purpose);u(w,7);u(w,issued);u(w,8);u(w,expires);
  u(w,9);w.writeByteString(nonce);u(w,10);w.writeByteString(context);byte[] exact=w.toByteArray();
  var a=new AuthenticationAssertion(1,ID,STATE,gen,AUD,purpose,issued,expires,nonce,context,exact);
  byte[] signing=AuthenticationAssertionCodec.signingBytes(a,METHOD);Ed25519Signer s=new Ed25519Signer();s.init(true,key);s.update(signing,0,signing.length);
  return new SecuredAuthenticationAssertion(a,List.of(new AuthenticationProof(METHOD,s.generateSignature())));
 }
 private static void u(DeterministicCborWriter w,long n){w.writeUnsigned(n);}
 private static void error(ExternalOidcBindingError e,Runnable r){assertEquals(e,assertThrows(ExternalOidcBindingException.class,r::run).error());}
}
