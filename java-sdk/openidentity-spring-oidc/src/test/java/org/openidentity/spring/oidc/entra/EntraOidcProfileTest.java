package org.openidentity.spring.oidc.entra;

import org.junit.jupiter.api.Test;
import org.openidentity.oidc.VerifiedExternalOidcPrincipal;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class EntraOidcProfileTest {
 private static final String TENANT="11111111-2222-3333-4444-555555555555";
 @Test void singleTenantIssuerAndClientArePinned(){
  var p=new EntraOidcProfile(TENANT,Set.of("client-1"));
  assertEquals("https://login.microsoftonline.com/"+TENANT+"/v2.0",p.issuer());
  assertTrue(p.providerTrusted(p.issuer()));assertTrue(p.clientAllowed(p.issuer(),"client-1"));assertFalse(p.clientAllowed(p.issuer(),"other"));
 }
 @Test void tidMustMatchIssuerTenantAndProviderClaimsStayAssurance(){
  var p=new EntraOidcProfile(TENANT,Set.of("client-1"));
  var principal=new VerifiedExternalOidcPrincipal(p.issuer(),"pairwise-sub","client-1",null,null,List.of(),Map.of("tid",TENANT,"oid","aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","preferred_username","user@example.test"));
  p.validate(principal);var a=p.normalizedAssurance(principal);
  assertEquals(TENANT,a.get("tid"));assertEquals("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",a.get("oid"));assertEquals("user@example.test",a.get("preferred_username"));
  assertEquals("pairwise-sub",principal.subject());
 }
 @Test void wrongTenantFailsClosed(){
  var p=new EntraOidcProfile(TENANT,Set.of("client-1"));
  var principal=new VerifiedExternalOidcPrincipal(p.issuer(),"sub","client-1",null,null,List.of(),Map.of("tid","99999999-2222-3333-4444-555555555555"));
  assertThrows(IllegalArgumentException.class,()->p.validate(principal));
 }
 @Test void registrationUsesTenantScopedV2Endpoints(){
  var r=EntraClientRegistrationFactory.create("entra",TENANT,"client-1","secret");
  assertEquals("https://login.microsoftonline.com/"+TENANT+"/v2.0",r.getProviderDetails().getIssuerUri());
  assertEquals("https://login.microsoftonline.com/"+TENANT+"/oauth2/v2.0/authorize",r.getProviderDetails().getAuthorizationUri());
  assertEquals("https://login.microsoftonline.com/"+TENANT+"/oauth2/v2.0/token",r.getProviderDetails().getTokenUri());
  assertEquals("sub",r.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName());
  assertTrue(r.getScopes().containsAll(Set.of("openid","profile","email")));
 }
}
