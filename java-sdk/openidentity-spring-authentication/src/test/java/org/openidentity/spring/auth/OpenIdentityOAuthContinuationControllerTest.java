package org.openidentity.spring.auth;
import org.junit.jupiter.api.Test;import org.openidentity.auth.Oi015Verifier;import java.security.SecureRandom;import java.time.*;import static org.junit.jupiter.api.Assertions.*;
class OpenIdentityOAuthContinuationControllerTest {
 static OpenIdentityOAuthContinuationController controller(){
  var service=new OpenIdentityAuthenticationService(new Oi015Verifier(x->null,60),new InMemoryOpenIdentityAuthenticationChallengeStore(),new byte[]{1},Clock.fixed(Instant.ofEpochSecond(1000),ZoneOffset.UTC),new SecureRandom(),30);
  return new OpenIdentityOAuthContinuationController(service,new InMemoryOpenIdentityAuthenticationContinuationStore());
 }
 @Test void acceptsOnlyLocalOAuthAuthorizationContinuation(){
  var c=controller();assertNotNull(c.challenge(new OpenIdentityOAuthContinuationController.ChallengeRequest("/oauth2/authorize?client_id=c")).get("challengeId"));
  assertThrows(IllegalArgumentException.class,()->c.challenge(new OpenIdentityOAuthContinuationController.ChallengeRequest("https://evil.example/oauth2/authorize")));
  assertThrows(IllegalArgumentException.class,()->c.challenge(new OpenIdentityOAuthContinuationController.ChallengeRequest("//evil.example/oauth2/authorize?x=1")));
  assertThrows(IllegalArgumentException.class,()->c.challenge(new OpenIdentityOAuthContinuationController.ChallengeRequest("/other")));
 }
 @Test void continuationIsSingleUse(){
  var s=new InMemoryOpenIdentityAuthenticationContinuationStore();s.put("x","/oauth2/authorize?a=b");assertEquals("/oauth2/authorize?a=b",s.consume("x"));assertNull(s.consume("x"));
 }
}