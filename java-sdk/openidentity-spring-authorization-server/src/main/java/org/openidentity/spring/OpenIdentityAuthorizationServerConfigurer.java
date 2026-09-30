package org.openidentity.spring;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import java.util.Objects;

public final class OpenIdentityAuthorizationServerConfigurer {
 private OpenIdentityAuthorizationServerConfigurer(){}

 public static void configure(
   HttpSecurity http,
   OpenIdentityTokenExchangeAuthenticationConverter converter,
   OpenIdentityTokenExchangeAuthenticationProvider provider) throws Exception {
  Objects.requireNonNull(http);Objects.requireNonNull(converter);Objects.requireNonNull(provider);
  http.oauth2AuthorizationServer(authorizationServer->
      authorizationServer.tokenEndpoint(tokenEndpoint->
          tokenEndpoint.accessTokenRequestConverter(converter).authenticationProvider(provider)));
 }
}
