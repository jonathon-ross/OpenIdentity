package org.openidentity.spring;
import org.openidentity.oauth.AuthorizationDecision;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import java.util.List;
public final class OpenIdentityAuthorizationDecisionAuthentication extends AbstractAuthenticationToken {
 private final AuthorizationDecision decision;
 public OpenIdentityAuthorizationDecisionAuthentication(AuthorizationDecision decision){super(List.of());this.decision=decision;setAuthenticated(true);}
 public AuthorizationDecision decision(){return decision;}@Override public Object getCredentials(){return "";}@Override public Object getPrincipal(){return decision;}
}
