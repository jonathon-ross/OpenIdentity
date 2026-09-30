package org.openidentity.spring;

import org.junit.jupiter.api.Test;
import org.openidentity.oauth.*;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class OpenIdentitySpringAdapterTest {
 static String b64(byte[] b){return Base64.getUrlEncoder().withoutPadding().encodeToString(b);}
 static String jkt(){return b64(new byte[32]);}

 @Test void converterClaimsOnlyExactOpenIdentityTokenExchange(){
  var req=new MockHttpServletRequest();req.setParameter("grant_type","urn:ietf:params:oauth:grant-type:token-exchange");
  req.setParameter("subject_token_type",OpenIdentityOAuthParameters.SUBJECT_TOKEN_TYPE);req.setParameter("actor_token_type",OpenIdentityOAuthParameters.ACTOR_TOKEN_TYPE);
  req.setParameter("subject_token",b64(new byte[]{1,2}));req.setParameter("actor_token",b64(new byte[]{3,4}));req.setParameter("scope","read write");
  var client=new TestingAuthenticationToken("client","",List.of());client.setAuthenticated(true);SecurityContextHolder.getContext().setAuthentication(client);
  try{
   var c=new OpenIdentityTokenExchangeAuthenticationConverter(r->jkt(),r->new byte[32]);
   var a=(OpenIdentityTokenExchangeAuthenticationToken)c.convert(req);assertNotNull(a);assertEquals(List.of("read","write"),a.scopes());assertEquals(jkt(),a.dpopJkt());
  }finally{SecurityContextHolder.clearContext();}
 }

 @Test void converterRejectsPaddedTokenTransport(){
  var req=new MockHttpServletRequest();req.setParameter("grant_type","urn:ietf:params:oauth:grant-type:token-exchange");
  req.setParameter("subject_token_type",OpenIdentityOAuthParameters.SUBJECT_TOKEN_TYPE);req.setParameter("actor_token_type",OpenIdentityOAuthParameters.ACTOR_TOKEN_TYPE);
  req.setParameter("subject_token","AQ==");req.setParameter("actor_token","Aw");
  var client=new TestingAuthenticationToken("client","",List.of());client.setAuthenticated(true);SecurityContextHolder.getContext().setAuthentication(client);
  try{var c=new OpenIdentityTokenExchangeAuthenticationConverter(r->jkt(),r->new byte[32]);assertThrows(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class,()->c.convert(req));}
  finally{SecurityContextHolder.clearContext();}
 }

 @Test void targetFailureMapsToRfc8693InvalidTargetWithoutSensitiveDetail(){
  var e=new ProfileException(ProfileError.TARGET_SCOPE_PAIR_NOT_AUTHORIZED);
  var o=OpenIdentityProfileErrorMapper.toOAuth(e);assertEquals("invalid_target",o.getError().getErrorCode());
  assertEquals("The token exchange request could not be accepted.",o.getError().getDescription());assertFalse(o.getError().getDescription().contains("TARGET_SCOPE"));
 }

 @Test void jwtProjectionUsesFrozenDecision(){
  byte[] root=new byte[32],actor=new byte[32];Arrays.fill(actor,(byte)7);
  var d=new AuthorizationDecision(root,actor,List.of("https://api.example.test/"),List.of("read"),jkt(),1000,1180);
  var b=org.springframework.security.oauth2.jwt.JwtClaimsSet.builder();OpenIdentityJwtClaims.apply(b,d);var c=b.build().getClaims();
  assertEquals(HexFormat.of().formatHex(root),c.get("sub"));assertEquals(List.of("https://api.example.test/"),c.get("aud"));assertEquals("read",c.get("scope"));
  assertEquals(HexFormat.of().formatHex(actor),((Map<?,?>)c.get("act")).get("sub"));assertEquals(jkt(),((Map<?,?>)c.get("cnf")).get("jkt"));
 }
}
