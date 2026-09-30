package org.openidentity.spring;

import org.springframework.security.oauth2.server.authorization.token.*;

public final class OpenIdentityJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
 @Override public void customize(JwtEncodingContext context){
  var d=OpenIdentityDecisionResolver.from(context);if(d!=null)OpenIdentityJwtClaims.apply(context.getClaims(),d);
 }
}
