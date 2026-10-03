package org.openidentity.spring.auth;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;import org.bouncycastle.crypto.signers.Ed25519Signer;import org.junit.jupiter.api.Test;import org.openidentity.auth.*;import org.openidentity.crypto.Sha256Multihash;import org.springframework.mock.web.*;import org.springframework.security.core.context.SecurityContext;import org.springframework.security.web.context.HttpSessionSecurityContextRepository;import java.nio.charset.StandardCharsets;import java.security.*;import java.time.*;import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
class OpenIdentityAuthenticationHttpControllerTest {
 static byte[] h(String s){try{return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));}catch(Exception e){throw new RuntimeException(e);}}
 static byte[] sign(Ed25519PrivateKeyParameters k,byte[] m){var s=new Ed25519Signer();s.init(true,k);s.update(m,0,m.length);return s.generateSignature();}
 record F(OpenIdentityAuthenticationHttpController controller,Ed25519PrivateKeyParameters key,byte[] id,byte[] state,byte[] method,byte[] audience){}
 static F fixture(){
  byte[] id=h("http-id"),state=Sha256Multihash.digest(h("http-state")),method=Arrays.copyOf(h("http-method"),16),aud="https://issuer.example".getBytes(StandardCharsets.UTF_8);var key=new Ed25519PrivateKeyParameters(h("http-key"),0);
  var policy=new AuthenticationPolicySnapshot(4,1,List.of(new AuthenticationMethod(method,key.generatePublicKey().getEncoded())));var verifier=new Oi015Verifier(x->new CurrentAuthenticationState(id,state,true,policy),120);
  var service=new OpenIdentityAuthenticationService(verifier,new InMemoryOpenIdentityAuthenticationChallengeStore(),aud,Clock.fixed(Instant.ofEpochSecond(1000),ZoneOffset.UTC),new SecureRandom(),60);
  return new F(new OpenIdentityAuthenticationHttpController(service),key,id,state,method,aud);
 }
 static byte[] secured(F f,String requestTarget,Map<String,Object> response){
  var hex=HexFormat.of();byte[] nonce=hex.parseHex((String)response.get("nonceHex")),ctx=hex.parseHex((String)response.get("contextHashHex"));
  var raw=new AuthenticationAssertion(1,f.id,f.state,4,f.audience,OpenIdentityAuthenticationService.PURPOSE,1000,1060,nonce,ctx,new byte[0]);byte[] exact=Oi015Codec.encodeAssertion(raw);
  var a=new AuthenticationAssertion(1,f.id,f.state,4,f.audience,OpenIdentityAuthenticationService.PURPOSE,1000,1060,nonce,ctx,exact);byte[] sig=sign(f.key,AuthenticationAssertionCodec.signingBytes(a,f.method));return Oi015Codec.encode(a,List.of(new AuthenticationProof(f.method,sig)));
 }
 @Test void challengeExposesAllRequiredBindings(){
  var f=fixture();String target="/oauth2/authorize?client_id=c";var out=f.controller.challenge(new OpenIdentityAuthenticationHttpController.ChallengeRequest(target));
  assertNotNull(out.get("challengeId"));assertEquals(OpenIdentityAuthenticationService.PURPOSE,out.get("purpose"));assertEquals(64,((String)out.get("nonceHex")).length());assertEquals(68,((String)out.get("contextHashHex")).length());
 }
 @Test void successfulVerificationPersistsOpenIdentityPrincipalInSession(){
  var f=fixture();String target="/oauth2/authorize?client_id=c";var ch=f.controller.challenge(new OpenIdentityAuthenticationHttpController.ChallengeRequest(target));byte[] assertion=secured(f,target,ch);
  var req=new MockHttpServletRequest();var res=new MockHttpServletResponse();var body=new OpenIdentityAuthenticationHttpController.VerifyRequest((String)ch.get("challengeId"),Base64.getUrlEncoder().withoutPadding().encodeToString(assertion));
  var response=f.controller.verify(body,req,res);assertEquals(200,response.getStatusCode().value());assertEquals(HexFormat.of().formatHex(f.id),response.getBody().get("identity"));
  MockHttpSession session=(MockHttpSession)req.getSession(false);assertNotNull(session);SecurityContext context=(SecurityContext)session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);assertNotNull(context);assertTrue(context.getAuthentication() instanceof OpenIdentityNativeAuthenticationToken);assertArrayEquals(f.id,((OpenIdentityNativeAuthenticationToken)context.getAuthentication()).openIdentityId());
 }
 @Test void rejectionIsUniformAndChallengeCannotReplay(){
  var f=fixture();var ch=f.controller.challenge(new OpenIdentityAuthenticationHttpController.ChallengeRequest("/oauth2/authorize"));var req=new MockHttpServletRequest();var res=new MockHttpServletResponse();
  var bad=new OpenIdentityAuthenticationHttpController.VerifyRequest((String)ch.get("challengeId"),Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[]{1}));
  var first=f.controller.verify(bad,req,res);assertEquals(401,first.getStatusCode().value());assertEquals(Map.of("status","REJECTED"),first.getBody());
  var second=f.controller.verify(bad,new MockHttpServletRequest(),new MockHttpServletResponse());assertEquals(401,second.getStatusCode().value());assertEquals(Map.of("status","REJECTED"),second.getBody());
 }
}