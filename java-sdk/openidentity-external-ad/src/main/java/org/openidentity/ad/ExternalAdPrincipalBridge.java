package org.openidentity.ad;
public final class ExternalAdPrincipalBridge {
 private ExternalAdPrincipalBridge(){}
 public static InMemoryExternalAdBindingRegistry.Principal registryPrincipal(VerifiedAdPrincipal p){
  if(p==null)throw new IllegalArgumentException("verified principal required");
  return new InMemoryExternalAdBindingRegistry.Principal(p.directoryId(),p.objectGuid(),p.serviceId(),p.authenticationMechanism(),p.channelTrusted(),p.accountUsable(),p.assuranceSufficient());
 }
}