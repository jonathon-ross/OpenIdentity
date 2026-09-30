package org.openidentity.spring;

import org.openidentity.oauth.AuthorizationDecision;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import java.util.*;

public final class OpenIdentityAuthenticatedGrant extends AbstractAuthenticationToken {
 private final Authentication clientPrincipal;
 private final AuthorizationDecision decision;
 private final ValidatedDpopProofResult dpop;
 public OpenIdentityAuthenticatedGrant(Authentication clientPrincipal,AuthorizationDecision decision,ValidatedDpopProofResult dpop){
  super(List.of());this.clientPrincipal=Objects.requireNonNull(clientPrincipal);this.decision=Objects.requireNonNull(decision);this.dpop=Objects.requireNonNull(dpop);setAuthenticated(true);
 }
 public AuthorizationDecision decision(){return decision;}public ValidatedDpopProofResult dpop(){return dpop;}
 @Override public Object getPrincipal(){return clientPrincipal;}@Override public Object getCredentials(){return "";}
}
