package org.openidentity.spring;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import java.util.Objects;

public final class OpenIdentityAuthorizationServerConfigurer {
 private OpenIdentityAuthorizationServerConfigurer(){}

 public static void configure(
   HttpSecurity http,
   OpenIdentityTokenExchangeAuthenticationConverter converter,
   OpenIdentityTokenExchangeAuthenticationProvider provider) throws Exception {
  Objects.requireNonNull(http);Objects.requireNonNull(converter);Objects.requireNonNull(provider);
  OAuth2AuthorizationServerConfigurer authorizationServer=new OAuth2AuthorizationServerConfigurer();
  http.securityMatcher(authorizationServer.getEndpointsMatcher())
      .with(authorizationServer,server->server.tokenEndpoint(tokenEndpoint->
          tokenEndpoint.accessTokenRequestConverter(converter).authenticationProvider(provider)));
 }
}
