package org.openidentity.spring;
import org.junit.jupiter.api.*;import org.springframework.security.authentication.AbstractAuthenticationToken;import org.springframework.security.core.*;import org.springframework.security.oauth2.core.*;import org.springframework.security.oauth2.jwt.*;import org.springframework.security.oauth2.server.authorization.*;import org.springframework.security.oauth2.server.authorization.client.*;import org.springframework.security.oauth2.server.authorization.context.*;import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;import org.springframework.security.oauth2.server.authorization.token.*;import java.time.*;import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
class OpenIdentityJwtCustomizerTest {
 @Test void accessTokenSubjectIsOpenIdentityIdentity(){var c=context(OAuth2TokenType.ACCESS_TOKEN,new OiPrincipal());new OpenIdentityJwtCustomizer().customize(c);assertEquals("42".repeat(32),c.getClaims().build().getSubject());assertFalse(c.getClaims().build().getClaims().containsKey("oi_identity"));}
 @Test void idTokenSubjectIsOpenIdentityIdentity(){var c=context(new OAuth2TokenType("id_token"),new OiPrincipal());new OpenIdentityJwtCustomizer().customize(c);assertEquals("42".repeat(32),c.getClaims().build().getSubject());}
 @Test void ordinaryPrincipalIsUntouched(){var c=context(OAuth2TokenType.ACCESS_TOKEN,new PlainPrincipal());new OpenIdentityJwtCustomizer().customize(c);assertNull(c.getClaims().build().getSubject());}
 private static JwtEncodingContext context(OAuth2TokenType type,Authentication principal){
  var client=RegisteredClient.withId("id").clientId("client").clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("https://client.example/callback").scope("openid").build();
  var as=new AuthorizationServerContext(){public String getIssuer(){return "https://issuer.example";}public AuthorizationServerSettings getAuthorizationServerSettings(){return AuthorizationServerSettings.builder().issuer(getIssuer()).build();}};
  return JwtEncodingContext.with(JwsHeader.with(() -> "RS256"),JwtClaimsSet.builder().issuer("https://issuer.example")).registeredClient(client).principal(principal).authorizationServerContext(as).authorizedScopes(Set.of("openid")).tokenType(type).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).build();
 }
 private static final class OiPrincipal extends AbstractAuthenticationToken implements OpenIdentityPrincipal{
  OiPrincipal(){super(List.of());setAuthenticated(true);}@Override public Object getPrincipal(){return "ignored";}@Override public Object getCredentials(){return "";}@Override public byte[] openIdentityId(){byte[] b=new byte[32];Arrays.fill(b,(byte)0x42);return b;}
 }
 private static final class PlainPrincipal extends AbstractAuthenticationToken{
  PlainPrincipal(){super(List.of());setAuthenticated(true);}@Override public Object getPrincipal(){return "alice";}@Override public Object getCredentials(){return "";}
 }
}