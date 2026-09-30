package org.openidentity.spring;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import java.util.*;

public final class OpenIdentityTokenExchangeAuthenticationToken extends AbstractAuthenticationToken {
 private final Authentication clientPrincipal;
 private final byte[] subjectToken,actorToken,actorNonce;
 private final String requestedTokenType,dpopJkt;
 private final List<String> resources,audiences,scopes;

 public OpenIdentityTokenExchangeAuthenticationToken(Authentication clientPrincipal,byte[] subjectToken,byte[] actorToken,byte[] actorNonce,
   String requestedTokenType,String dpopJkt,List<String> resources,List<String> audiences,List<String> scopes){
  super(List.of());this.clientPrincipal=Objects.requireNonNull(clientPrincipal);this.subjectToken=subjectToken.clone();this.actorToken=actorToken.clone();this.actorNonce=actorNonce.clone();
  this.requestedTokenType=requestedTokenType;this.dpopJkt=Objects.requireNonNull(dpopJkt);this.resources=List.copyOf(resources);this.audiences=List.copyOf(audiences);this.scopes=List.copyOf(scopes);
  setAuthenticated(false);
 }
 @Override public Object getPrincipal(){return clientPrincipal;}@Override public Object getCredentials(){return "";}
 public Authentication clientPrincipal(){return clientPrincipal;}public byte[] subjectToken(){return subjectToken.clone();}public byte[] actorToken(){return actorToken.clone();}public byte[] actorNonce(){return actorNonce.clone();}
 public String requestedTokenType(){return requestedTokenType;}public String dpopJkt(){return dpopJkt;}public List<String> resources(){return resources;}public List<String> audiences(){return audiences;}public List<String> scopes(){return scopes;}
}
