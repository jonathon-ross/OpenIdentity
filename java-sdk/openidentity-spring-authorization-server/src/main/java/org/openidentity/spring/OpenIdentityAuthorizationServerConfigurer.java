package org.openidentity.spring;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import java.util.Objects;

public final class OpenIdentityAuthorizationServerConfigurer {
 private OpenIdentityAuthorizationServerConfigurer(){}

 public static void configure(
   HttpSecurity http,
   OpenIdentityTokenExchangeAuthenticationConverter converter,
   OpenIdentityTokenExchangeAuthenticationProvider provider) throws Exception {
  Objects.requireNonNull(http);Objects.requireNonNull(converter);Objects.requireNonNull(provider);
  OAuth2AuthorizationServerConfigurer authorizationServer=http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
  if(authorizationServer==null)throw new IllegalStateException("OAuth2AuthorizationServerConfigurer must be applied before OpenIdentity configuration");
  authorizationServer.tokenEndpoint(tokenEndpoint->
      tokenEndpoint.accessTokenRequestConverter(converter).authenticationProvider(provider));
 }
}
