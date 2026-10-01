package org.openidentity.spring.oidc;

import org.junit.jupiter.api.Test;
import org.openidentity.auth.*;
import org.openidentity.oidc.*;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import java.time.Instant;import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class ExternalOidcBindingHttpSessionTest {
 @Test void pendingHttpRequestIsBoundToValidatedOidcPrincipalAndSession(){
  byte[] id=new byte[32];var policy=new InMemoryExternalOidcBindingRegistry.Policy(){public boolean providerTrusted(String i){return true;}public boolean clientAllowed(String i,String c){return true;}public boolean identityActive(byte[] i){return true;}public long currentAuthenticationGeneration(byte[] i){return 7;}public boolean assuranceSufficient(VerifiedExternalOidcPrincipal p){return true;}};
  var verifier=new Oi015Verifier(identity->null,300);var ceremony=new ExternalOidcBindingCeremony(verifier,new InMemoryExternalOidcBindingRegistry(),policy);
  var reg=ClientRegistration.withRegistrationId("entra").clientId("client-1").clientSecret("secret").authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("http://localhost/callback").scope("openid").authorizationUri("https://idp/authorize").tokenUri("https://idp/token").jwkSetUri("https://idp/jwks").issuerUri("https://idp").userNameAttributeName("sub").clientName("test").build();
  Instant now=Instant.now();var user=new DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_USER")),new OidcIdToken("token",now,now.plusSeconds(60),Map.of("iss","https://idp","sub","subject-a","aud",List.of("client-1"),"iat",now,"exp",now.plusSeconds(60))));
  var auth=new OAuth2AuthenticationToken(user,user.getAuthorities(),"entra");var session=new MockHttpSession();
  var http=new ExternalOidcBindingHttpSession(new SpringOidcPrincipalMapper(),new InMemoryClientRegistrationRepository(reg),ceremony);
  var request=http.begin(session,auth,id,1790841600L,null);var pending=http.pending(session);
  assertEquals(ExternalOidcBindingCeremony.BIND_PURPOSE,request.purpose());assertNotNull(pending);assertEquals(request.contextHashHex(),HexFormat.of().formatHex(pending.pending().contextHash()));
  assertEquals("https://idp",pending.pending().principal().issuer());assertEquals("subject-a",pending.pending().principal().subject());assertEquals("client-1",pending.pending().principal().clientId());assertEquals(7,pending.pending().generation());
  http.clear(session);assertNull(http.pending(session));
 }
}
