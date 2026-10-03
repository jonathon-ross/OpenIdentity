package org.openidentity.spring;

import org.openidentity.oauth.AuthorizationDecision;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.*;
import java.util.*;

public final class OpenIdentitySpringTokenIssuer {
 private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
 public OpenIdentitySpringTokenIssuer(OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator){this.tokenGenerator=Objects.requireNonNull(tokenGenerator);}

 public OAuth2AccessTokenAuthenticationToken issue(OAuth2ClientAuthenticationToken client,OpenIdentityAuthenticatedGrant grant){
  RegisteredClient registered=client.getRegisteredClient();if(registered==null)throw invalid();
  AuthorizationDecision d=grant.decision();
  var context=DefaultOAuth2TokenContext.builder()
      .registeredClient(registered)
      .principal(client)
      .authorizationServerContext(AuthorizationServerContextHolder.getContext())
      .authorizationGrantType(new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:token-exchange"))
      .authorizationGrant(grant)
      .authorizedScopes(new LinkedHashSet<>(d.scopes()))
      .tokenType(OAuth2TokenType.ACCESS_TOKEN)
      .put(OAuth2TokenContext.DPOP_PROOF_KEY,grant.dpop().proof())
      .build();
  OAuth2Token generated=tokenGenerator.generate(context);if(generated==null)throw invalid();
  OAuth2AccessToken access;
  if(generated instanceof OAuth2AccessToken a)access=new OAuth2AccessToken(new OAuth2AccessToken.TokenType("DPoP"),a.getTokenValue(),a.getIssuedAt(),a.getExpiresAt(),a.getScopes());
  else access=new OAuth2AccessToken(new OAuth2AccessToken.TokenType("DPoP"),generated.getTokenValue(),generated.getIssuedAt(),generated.getExpiresAt(),new LinkedHashSet<>(d.scopes()));
  Map<String,Object> additional=new LinkedHashMap<>();additional.put("issued_token_type","urn:ietf:params:oauth:token-type:access_token");
  return new OAuth2AccessTokenAuthenticationToken(registered,client,access,null,additional);
 }
 private static OAuth2AuthenticationException invalid(){return OpenIdentityProfileErrorMapper.toOAuth(new org.openidentity.oauth.ProfileException(org.openidentity.oauth.ProfileError.INVALID_REQUEST));}
}
