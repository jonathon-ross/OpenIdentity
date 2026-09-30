package org.openidentity.spring;

import org.springframework.security.oauth2.server.authorization.token.*;
import java.util.Objects;

public final class OpenIdentityJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
 private final java.util.function.Function<JwtEncodingContext,org.openidentity.oauth.AuthorizationDecision> decisionResolver;
 public OpenIdentityJwtCustomizer(java.util.function.Function<JwtEncodingContext,org.openidentity.oauth.AuthorizationDecision> decisionResolver){
  this.decisionResolver=Objects.requireNonNull(decisionResolver);
 }
 @Override public void customize(JwtEncodingContext context){
  var d=decisionResolver.apply(context);if(d!=null)OpenIdentityJwtClaims.apply(context.getClaims(),d);
 }
}
