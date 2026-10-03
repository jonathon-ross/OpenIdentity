package org.openidentity.spring.auth;
import org.junit.jupiter.api.Test;import org.openidentity.auth.Oi015Verifier;import org.springframework.mock.web.*;import java.security.SecureRandom;import java.time.*;import static org.junit.jupiter.api.Assertions.*;
class OpenIdentityAuthenticatorTransactionControllerTest {
 static OpenIdentityAuthenticatorTransactionController controller(){
  var service=new OpenIdentityAuthenticationService(new Oi015Verifier(x->null,60),new InMemoryOpenIdentityAuthenticationChallengeStore(),new byte[]{1},Clock.fixed(Instant.ofEpochSecond(1000),ZoneOffset.UTC),new SecureRandom(),60);
  return new OpenIdentityAuthenticatorTransactionController(service,new OpenIdentityAuthenticationTransactionStore());
 }
 @Test void rejectsNonLocalAuthorizationTarget(){
  var c=controller();assertThrows(IllegalArgumentException.class,()->c.create(new OpenIdentityAuthenticatorTransactionController.CreateRequest("https://evil.example/oauth2/authorize")));
  assertThrows(IllegalArgumentException.class,()->c.create(new OpenIdentityAuthenticatorTransactionController.CreateRequest("//evil.example/oauth2/authorize?x=1")));
  assertThrows(IllegalArgumentException.class,()->c.create(new OpenIdentityAuthenticatorTransactionController.CreateRequest("/other")));
 }
 @Test void unknownTransactionCannotComplete(){
  var r=controller().complete("missing",new MockHttpServletRequest(),new MockHttpServletResponse());assertEquals(409,r.getStatusCode().value());assertEquals("UNKNOWN",r.getBody().get("status"));
 }
 @Test void pendingTransactionCannotCompleteButRemainsPending(){
  var c=controller();var created=c.create(new OpenIdentityAuthenticatorTransactionController.CreateRequest("/oauth2/authorize?client_id=c"));String id=(String)created.get("transactionId");
  var first=c.complete(id,new MockHttpServletRequest(),new MockHttpServletResponse());assertEquals(409,first.getStatusCode().value());assertEquals("PENDING",first.getBody().get("status"));
  var second=c.complete(id,new MockHttpServletRequest(),new MockHttpServletResponse());assertEquals(409,second.getStatusCode().value());assertEquals("PENDING",second.getBody().get("status"));
 }
 @Test void malformedAssertionRejectsTransactionAndCannotRetry(){
  var c=controller();var created=c.create(new OpenIdentityAuthenticatorTransactionController.CreateRequest("/oauth2/authorize?client_id=c"));String id=(String)created.get("transactionId");
  var bad=c.assertion(id,new OpenIdentityAuthenticatorTransactionController.AssertionRequest("AQ"));assertEquals(401,bad.getStatusCode().value());
  var again=c.assertion(id,new OpenIdentityAuthenticatorTransactionController.AssertionRequest("AQ"));assertEquals(409,again.getStatusCode().value());
  assertEquals("REJECTED",c.status(id).getBody().get("status"));
 }
}