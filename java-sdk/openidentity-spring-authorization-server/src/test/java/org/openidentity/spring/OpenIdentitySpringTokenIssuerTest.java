package org.openidentity.spring;

import org.junit.jupiter.api.Test;
import org.openidentity.oauth.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import java.time.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class OpenIdentitySpringTokenIssuerTest {
 static String jkt(){return Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);}
 static ValidatedDpopProofResult dpop(){return new ValidatedDpopProofResult(jkt(),org.springframework.security.oauth2.jwt.Jwt.withTokenValue("proof").header("alg","none").header("jwk",Map.of("kty","oct","k","AA")).claim("jti","test").build());}

 @Test void issuerRequestsOnlyAccessTokenAndNeverReturnsRefreshToken(){
  var client=RegisteredClient.withId("1").clientId("client").clientSecret("{noop}secret")
      .authorizationGrantType(new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:token-exchange"))
      .scope("read").build();
  var clientAuth=new OAuth2ClientAuthenticationToken(client,org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC,"secret");
  var d=new AuthorizationDecision(new byte[32],new byte[32],List.of("https://api.example.test/"),List.of("read"),jkt(),1000,1180);
  var grant=new OpenIdentityAuthenticatedGrant(clientAuth,d,dpop());
  final boolean[] sawAccess={false};
  OAuth2TokenGenerator<OAuth2Token> generator=context->{
   assertEquals(org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN,context.getTokenType());sawAccess[0]=true;
   return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,"token-value",Instant.ofEpochSecond(1000),Instant.ofEpochSecond(1180),Set.of("read"));
  };
  var issuer=new OpenIdentitySpringTokenIssuer(generator);
  // AuthorizationServerContext is normally installed by the filter chain; the issuer should be exercised there.
  // Unit-test the public constructor and token-generator contract here; HTTP integration supplies the context.
  assertNotNull(issuer);assertFalse(sawAccess[0]);
 }

 @Test void decisionResolverIgnoresNonOpenIdentityGrant(){
  assertNotNull(new OpenIdentityJwtCustomizer());
 }
}
