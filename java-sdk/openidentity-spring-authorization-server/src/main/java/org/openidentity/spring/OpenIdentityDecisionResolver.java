package org.openidentity.spring;

import org.openidentity.oauth.AuthorizationDecision;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

public final class OpenIdentityDecisionResolver {
 private OpenIdentityDecisionResolver(){}
 public static AuthorizationDecision from(JwtEncodingContext context){
  return context.getAuthorizationGrant() instanceof OpenIdentityAuthenticatedGrant g ? g.decision() : null;
 }
}
