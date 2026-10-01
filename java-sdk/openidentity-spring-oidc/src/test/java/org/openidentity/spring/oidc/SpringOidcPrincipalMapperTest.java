package org.openidentity.spring.oidc;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.*;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import java.time.Instant;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class SpringOidcPrincipalMapperTest {
 @Test void mapsOnlyFrozenIdentityAndTransientAssuranceSemantics(){
  Instant now=Instant.ofEpochSecond(1790841600L);
  OidcIdToken token=new OidcIdToken("token",now,now.plusSeconds(300),Map.of(
      "iss","https://idp.example.test","sub","subject-123","aud",List.of("client-1"),
      "iat",now,"exp",now.plusSeconds(300),"auth_time",now.minusSeconds(30),
      "acr","urn:acr:test","amr",List.of("pwd","mfa"),
      "email","user@example.test","groups",List.of("engineering")));
  var user=new DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_USER")),token);
  var reg=ClientRegistration.withRegistrationId("test").clientId("client-1").clientSecret("secret")
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .redirectUri("https://rp.example.test/login/oauth2/code/test")
      .scope("openid").authorizationUri("https://idp.example.test/authorize")
      .tokenUri("https://idp.example.test/token").jwkSetUri("https://idp.example.test/jwks")
      .issuerUri("https://idp.example.test").userNameAttributeName("sub").clientName("test").build();

  var p=new SpringOidcPrincipalMapper().map(user,reg);
  assertEquals("https://idp.example.test",p.issuer());assertEquals("subject-123",p.subject());assertEquals("client-1",p.clientId());
  assertEquals(now.minusSeconds(30).getEpochSecond(),p.authenticatedAt());assertEquals("urn:acr:test",p.acr());assertEquals(List.of("pwd","mfa"),p.amr());
  assertEquals("user@example.test",p.providerAssurance().get("email"));assertEquals(List.of("engineering"),p.providerAssurance().get("groups"));
  assertFalse(p.providerAssurance().containsKey("iss"));assertFalse(p.providerAssurance().containsKey("sub"));assertFalse(p.providerAssurance().containsKey("acr"));
 }
}
