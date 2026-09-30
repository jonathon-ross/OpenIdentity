package org.openidentity.spring;

import org.openidentity.oauth.AuthorizationDecision;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import java.util.*;

public final class OpenIdentityAuthenticatedGrant extends AbstractAuthenticationToken {
 private final Authentication clientPrincipal;
 private final AuthorizationDecision decision;
 public OpenIdentityAuthenticatedGrant(Authentication clientPrincipal,AuthorizationDecision decision){
  super(List.of());this.clientPrincipal=Objects.requireNonNull(clientPrincipal);this.decision=Objects.requireNonNull(decision);setAuthenticated(true);
 }
 public AuthorizationDecision decision(){return decision;}
 @Override public Object getPrincipal(){return clientPrincipal;}@Override public Object getCredentials(){return "";}
}
