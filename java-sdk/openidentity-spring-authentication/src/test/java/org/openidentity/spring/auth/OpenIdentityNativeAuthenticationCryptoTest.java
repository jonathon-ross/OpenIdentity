package org.openidentity.spring.auth;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;import org.bouncycastle.crypto.signers.Ed25519Signer;import org.junit.jupiter.api.Test;import org.openidentity.auth.*;import org.openidentity.crypto.Sha256Multihash;import java.nio.charset.StandardCharsets;import java.security.*;import java.time.*;import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
class OpenIdentityNativeAuthenticationCryptoTest {
 static byte[] h(String s){try{return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));}catch(Exception e){throw new RuntimeException(e);}}
 static byte[] sign(Ed25519PrivateKeyParameters k,byte[] m){var s=new Ed25519Signer();s.init(true,k);s.update(m,0,m.length);return s.generateSignature();}
 record Fixture(OpenIdentityAuthenticationService service,Ed25519PrivateKeyParameters key,byte[] id,byte[] state,byte[] method,byte[] audience,byte[] context){}
 static Fixture fixture(long generation){
  byte[] id=h("native-id"),state=Sha256Multihash.digest(h("native-state")),method=Arrays.copyOf(h("native-method"),16),aud="https://issuer.example".getBytes(StandardCharsets.UTF_8),ctx=OpenIdentityAuthenticationContext.oauthAuthorizationContext("/oauth2/authorize?client_id=c");
  var key=new Ed25519PrivateKeyParameters(h("native-private"),0);var policy=new AuthenticationPolicySnapshot(generation,1,List.of(new AuthenticationMethod(method,key.generatePublicKey().getEncoded())));
  var verifier=new Oi015Verifier(x->new CurrentAuthenticationState(id,state,true,policy),120);
  var service=new OpenIdentityAuthenticationService(verifier,new InMemoryOpenIdentityAuthenticationChallengeStore(),aud,Clock.fixed(Instant.ofEpochSecond(1000),ZoneOffset.UTC),new SecureRandom(),60);
  return new Fixture(service,key,id,state,method,aud,ctx);
 }
 static byte[] assertion(Fixture f,OpenIdentityAuthenticationService.IssuedChallenge issued,long generation,byte[] nonce,byte[] context,boolean corrupt){
  var c=issued.challenge();var raw=new AuthenticationAssertion(1,f.id,f.state,generation,f.audience,OpenIdentityAuthenticationService.PURPOSE,1000,1060,nonce,context,new byte[0]);
  byte[] exact=Oi015Codec.encodeAssertion(raw);var a=new AuthenticationAssertion(1,f.id,f.state,generation,f.audience,OpenIdentityAuthenticationService.PURPOSE,1000,1060,nonce,context,exact);
  byte[] sig=sign(f.key,AuthenticationAssertionCodec.signingBytes(a,f.method));if(corrupt)sig[0]^=1;
  return Oi015Codec.encode(a,List.of(new AuthenticationProof(f.method,sig)));
 }
 @Test void verifiesRealCanonicalOi015AndProducesPrincipal(){
  var f=fixture(7);var issued=f.service.issue(f.context);byte[] bytes=assertion(f,issued,7,issued.challenge().nonce(),f.context,false);
  var token=f.service.verify(issued.challengeId(),bytes);assertArrayEquals(f.id,token.openIdentityId());assertEquals(HexFormat.of().formatHex(f.id),token.getPrincipal());
 }
 @Test void rejectsBadSignatureAndBurnsChallenge(){
  var f=fixture(7);var issued=f.service.issue(f.context);assertThrows(RuntimeException.class,()->f.service.verify(issued.challengeId(),assertion(f,issued,7,issued.challenge().nonce(),f.context,true)));assertThrows(IllegalArgumentException.class,()->f.service.verify(issued.challengeId(),new byte[]{1}));
 }
 @Test void rejectsWrongNonce(){var f=fixture(7);var i=f.service.issue(f.context);assertThrows(RuntimeException.class,()->f.service.verify(i.challengeId(),assertion(f,i,7,h("wrong"),f.context,false)));}
 @Test void rejectsWrongContext(){var f=fixture(7);var i=f.service.issue(f.context);byte[] other=OpenIdentityAuthenticationContext.oauthAuthorizationContext("/other");assertThrows(RuntimeException.class,()->f.service.verify(i.challengeId(),assertion(f,i,7,i.challenge().nonce(),other,false)));}
 @Test void rejectsStaleGeneration(){var f=fixture(8);var i=f.service.issue(f.context);assertThrows(RuntimeException.class,()->f.service.verify(i.challengeId(),assertion(f,i,7,i.challenge().nonce(),f.context,false)));}
}