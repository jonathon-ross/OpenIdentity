package org.openidentity.spring;

import org.junit.jupiter.api.Test;
import org.openidentity.oauth.*;
import org.springframework.mock.web.*;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import java.time.Clock;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * HTTP-boundary contract test for the OpenIdentity token-exchange converter/provider.
 * Full Spring filter-chain token generation is covered by Spring's own authorization-server machinery;
 * this test pins the exact request surface handed to our adapter.
 */
final class OpenIdentityTokenEndpointHttpContractTest {
 static String b64(byte[] b){return Base64.getUrlEncoder().withoutPadding().encodeToString(b);}
 static String jkt(){return b64(new byte[32]);}
 static ValidatedDpopProofResult dpop(){return new ValidatedDpopProofResult(jkt(),org.springframework.security.oauth2.jwt.Jwt.withTokenValue("proof").header("alg","none").header("jwk",Map.of("kty","oct","k","AA")).claim("jti","test").build());}

 @Test void httpFormBecomesExactOpenIdentityGrantAuthentication(){
  MockHttpServletRequest r=new MockHttpServletRequest("POST","/oauth2/token");
  r.setContentType("application/x-www-form-urlencoded");
  r.setParameter("grant_type","urn:ietf:params:oauth:grant-type:token-exchange");
  r.setParameter("subject_token_type",OpenIdentityOAuthParameters.SUBJECT_TOKEN_TYPE);
  r.setParameter("actor_token_type",OpenIdentityOAuthParameters.ACTOR_TOKEN_TYPE);
  r.setParameter("subject_token",b64(new byte[]{1,2,3}));
  r.setParameter("actor_token",b64(new byte[]{4,5,6}));
  r.addParameter("resource","https://api.example.test/");
  r.setParameter("audience","records-service");
  r.setParameter("scope","records.read records.write");
  r.setParameter("dpop_jkt","attacker-controlled");

  var client=new TestingAuthenticationToken("agent-client","",List.of());client.setAuthenticated(true);
  SecurityContextHolder.getContext().setAuthentication(client);
  try{
   var converter=new OpenIdentityTokenExchangeAuthenticationConverter(req->dpop(),req->new byte[32]);
   var a=(OpenIdentityTokenExchangeAuthenticationToken)converter.convert(r);
   assertNotNull(a);assertArrayEquals(new byte[]{1,2,3},a.subjectToken());assertArrayEquals(new byte[]{4,5,6},a.actorToken());
   assertEquals(List.of("https://api.example.test/"),a.resources());assertEquals(List.of("records-service"),a.audiences());
   assertEquals(List.of("records.read","records.write"),a.scopes());assertEquals(jkt(),a.dpopJkt());assertNotEquals("attacker-controlled",a.dpopJkt());assertSame(client,a.clientPrincipal());
  }finally{SecurityContextHolder.clearContext();}
 }

 @Test void nonOpenIdentityTokenExchangeFallsThroughToSpring(){
  MockHttpServletRequest r=new MockHttpServletRequest("POST","/oauth2/token");
  r.setParameter("grant_type","urn:ietf:params:oauth:grant-type:token-exchange");
  r.setParameter("subject_token_type","urn:ietf:params:oauth:token-type:access_token");
  r.setParameter("actor_token_type","urn:ietf:params:oauth:token-type:access_token");
  var converter=new OpenIdentityTokenExchangeAuthenticationConverter(req->dpop(),req->new byte[32]);
  assertNull(converter.convert(r));
 }

 @Test void missingValidatedDpopFailsBeforeProvider(){
  MockHttpServletRequest r=new MockHttpServletRequest("POST","/oauth2/token");
  r.setParameter("grant_type","urn:ietf:params:oauth:grant-type:token-exchange");
  r.setParameter("subject_token_type",OpenIdentityOAuthParameters.SUBJECT_TOKEN_TYPE);r.setParameter("actor_token_type",OpenIdentityOAuthParameters.ACTOR_TOKEN_TYPE);
  r.setParameter("subject_token",b64(new byte[]{1}));r.setParameter("actor_token",b64(new byte[]{2}));
  var client=new TestingAuthenticationToken("client","",List.of());client.setAuthenticated(true);SecurityContextHolder.getContext().setAuthentication(client);
  try{
   var converter=new OpenIdentityTokenExchangeAuthenticationConverter(req->null,req->new byte[32]);
   var e=assertThrows(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class,()->converter.convert(r));
   assertEquals("invalid_request",e.getError().getErrorCode());
  }finally{SecurityContextHolder.clearContext();}
 }
}
