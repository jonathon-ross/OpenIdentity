package org.openidentity.spring.auth;
import org.junit.jupiter.api.Test;import org.openidentity.auth.*;import org.openidentity.core.*;import java.security.SecureRandom;import java.time.*;import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
class OpenIdentityAuthenticationServiceTest {
 @Test void challengeIsSingleUseEvenWhenVerificationFails(){
  byte[] id=new byte[32],hash=new byte[34],aud=new byte[]{1},ctx=new byte[34];hash[0]=0x12;hash[1]=0x20;ctx[0]=0x12;ctx[1]=0x20;
  AuthenticationStateResolver states=x->null;var verifier=new Oi015Verifier(states,60);var store=new InMemoryOpenIdentityAuthenticationChallengeStore();var svc=new OpenIdentityAuthenticationService(verifier,store,aud,Clock.fixed(Instant.ofEpochSecond(1000),ZoneOffset.UTC),new SecureRandom(),30);
  var issued=svc.issue(ctx);assertEquals(OpenIdentityAuthenticationService.PURPOSE,issued.challenge().purpose());assertEquals(32,issued.challenge().nonce().length);
  assertThrows(RuntimeException.class,()->svc.verify(issued.challengeId(),new byte[]{1}));
  var e=assertThrows(IllegalArgumentException.class,()->svc.verify(issued.challengeId(),new byte[]{1}));assertTrue(e.getMessage().contains("consumed"));
 }
 @Test void rejectsExpiredChallengeBeforeAssertionVerification(){
  byte[] aud={1},ctx=new byte[34];ctx[0]=0x12;ctx[1]=0x20;var clock=Clock.fixed(Instant.ofEpochSecond(1000),ZoneOffset.UTC);var store=new InMemoryOpenIdentityAuthenticationChallengeStore();var svc=new OpenIdentityAuthenticationService(new Oi015Verifier(x->null,60),store,aud,clock,new SecureRandom(),1);
  var issued=svc.issue(ctx);var later=new OpenIdentityAuthenticationService(new Oi015Verifier(x->null,60),store,aud,Clock.fixed(Instant.ofEpochSecond(1001),ZoneOffset.UTC),new SecureRandom(),1);
  assertThrows(IllegalArgumentException.class,()->later.verify(issued.challengeId(),new byte[]{1}));
 }
 @Test void nativeTokenIsGenericOpenIdentityPrincipal(){
  byte[] id=new byte[32],assertion=new byte[34];Arrays.fill(id,(byte)7);var t=new OpenIdentityNativeAuthenticationToken(id,assertion);assertTrue(t.isAuthenticated());assertArrayEquals(id,t.openIdentityId());assertTrue(t.getAuthorities().stream().anyMatch(a->a.getAuthority().equals("ROLE_OPENIDENTITY")));
 }
}