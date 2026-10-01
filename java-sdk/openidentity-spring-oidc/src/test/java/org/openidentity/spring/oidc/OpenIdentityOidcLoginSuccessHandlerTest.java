package org.openidentity.spring.oidc;

import org.junit.jupiter.api.Test;
import org.openidentity.oidc.*;
import org.springframework.mock.web.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.*;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import java.time.Instant;import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class OpenIdentityOidcLoginSuccessHandlerTest {
 private static final byte[] ID=new byte[32],CH=new byte[32];
 private static ClientRegistration reg(){return ClientRegistration.withRegistrationId("test").clientId("client-1").clientSecret("secret").authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("https://rp.test/login/oauth2/code/test").scope("openid").authorizationUri("https://idp.test/authorize").tokenUri("https://idp.test/token").jwkSetUri("https://idp.test/jwks").issuerUri("https://idp.test").userNameAttributeName("sub").clientName("test").build();}
 private static DefaultOidcUser user(String sub){Instant n=Instant.now();return new DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_USER")),new OidcIdToken("token",n,n.plusSeconds(300),Map.of("iss","https://idp.test","sub",sub,"aud",List.of("client-1"),"iat",n,"exp",n.plusSeconds(300))));}
 private static InMemoryExternalOidcBindingRegistry.Policy policy(){return new InMemoryExternalOidcBindingRegistry.Policy(){public boolean providerTrusted(String i){return true;}public boolean clientAllowed(String i,String c){return true;}public boolean identityActive(byte[] i){return true;}public long currentAuthenticationGeneration(byte[] i){return 3;}public boolean assuranceSufficient(VerifiedExternalOidcPrincipal p){return true;}};}
 private static OAuth2AuthenticationToken token(String sub){return new OAuth2AuthenticationToken(user(sub),List.of(new SimpleGrantedAuthority("ROLE_USER")),"test");}

 @Test void boundOidcLoginCreatesResolvedSessionAndRedirectsHome()throws Exception{
  var registry=new InMemoryExternalOidcBindingRegistry();registry.bind(new VerifiedExternalOidcPrincipal("https://idp.test","subject-a","client-1",null,null,List.of(),Map.of()),ID,1790841600L,null,CH,new InMemoryExternalOidcBindingRegistry.Authorization(true,"openidentity.external-oidc.bind",true,false),policy());
  var resolver=new SpringExternalOidcAuthenticationResolver(new SpringOidcPrincipalMapper(),registry,policy());
  var handler=new OpenIdentityOidcLoginSuccessHandler(new InMemoryClientRegistrationRepository(reg()),resolver);
  var req=new MockHttpServletRequest();var res=new MockHttpServletResponse();handler.onAuthenticationSuccess(req,res,token("subject-a"));
  assertEquals("/",res.getRedirectedUrl());assertNotNull(req.getSession(false));assertTrue(req.getSession(false).getAttribute(OpenIdentityOidcLoginSuccessHandler.SESSION_ATTRIBUTE) instanceof ResolvedExternalOidcAuthentication);
 }
 @Test void unboundOidcLoginRedirectsToLinkCeremony()throws Exception{
  var resolver=new SpringExternalOidcAuthenticationResolver(new SpringOidcPrincipalMapper(),new InMemoryExternalOidcBindingRegistry(),policy());
  var handler=new OpenIdentityOidcLoginSuccessHandler(new InMemoryClientRegistrationRepository(reg()),resolver);
  var req=new MockHttpServletRequest();var res=new MockHttpServletResponse();handler.onAuthenticationSuccess(req,res,token("unbound"));
  assertEquals("/openidentity/link",res.getRedirectedUrl());assertNull(req.getSession(false));
 }
}
