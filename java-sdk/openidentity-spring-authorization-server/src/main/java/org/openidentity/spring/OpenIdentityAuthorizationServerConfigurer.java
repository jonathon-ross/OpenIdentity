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
      .with(authorizationServer,server->server
          .tokenEndpoint(tokenEndpoint->tokenEndpoint.accessTokenRequestConverter(converter).authenticationProvider(provider))
          .authorizationServerMetadataEndpoint(metadata->metadata.authorizationServerMetadataCustomizer(builder->builder
              .claim("openidentity_token_exchange_profiles_supported",java.util.List.of("https://openidentity.org/oauth/profile/delegated-agent-v1"))
              .claim("openidentity_subject_token_types_supported",java.util.List.of(OpenIdentityOAuthParameters.SUBJECT_TOKEN_TYPE))
              .claim("openidentity_actor_token_types_supported",java.util.List.of(OpenIdentityOAuthParameters.ACTOR_TOKEN_TYPE))
              .claim("openidentity_dpop_required",true)
              .claim("openidentity_refresh_tokens_supported",false)
              .claim("openidentity_max_access_token_lifetime_seconds",300))));
 }
}
