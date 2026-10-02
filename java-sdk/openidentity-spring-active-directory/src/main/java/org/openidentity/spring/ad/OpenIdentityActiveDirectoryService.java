package org.openidentity.spring.ad;
import org.openidentity.ad.*;import java.util.*;
public final class OpenIdentityActiveDirectoryService {
 private final AdPrincipalResolver resolver;private final InMemoryExternalAdBindingRegistry registry;private final InMemoryExternalAdBindingRegistry.Policy policy;private final String profileId,serviceId;
 public OpenIdentityActiveDirectoryService(AdPrincipalResolver resolver,InMemoryExternalAdBindingRegistry registry,InMemoryExternalAdBindingRegistry.Policy policy,String profileId,String serviceId){this.resolver=Objects.requireNonNull(resolver);this.registry=Objects.requireNonNull(registry);this.policy=Objects.requireNonNull(policy);this.profileId=Objects.requireNonNull(profileId);this.serviceId=Objects.requireNonNull(serviceId);}
 public OpenIdentityActiveDirectoryAuthentication resolveEstablishedKerberosPrincipal(String kerberosPrincipal){
  if(kerberosPrincipal==null||kerberosPrincipal.isBlank())throw new IllegalArgumentException("kerberosPrincipal");
  var evidence=new AdAuthenticationEvidence(profileId,kerberosPrincipal,serviceId,ExternalAdBindingV1.KERBEROS_SPNEGO,true,Map.of("gssEstablished",true));
  VerifiedAdPrincipal verified=resolver.resolve(evidence);
  try{var resolved=registry.resolve(ExternalAdPrincipalBridge.registryPrincipal(verified),System.currentTimeMillis()/1000,policy);return new OpenIdentityActiveDirectoryAuthentication(kerberosPrincipal,verified,resolved.identity(),OpenIdentityActiveDirectoryAuthentication.BindingStatus.ACTIVE);}
  catch(ExternalAdBindingException e){if(e.error()!=ExternalAdBindingError.BINDING_NOT_FOUND)throw e;return new OpenIdentityActiveDirectoryAuthentication(kerberosPrincipal,verified,null,OpenIdentityActiveDirectoryAuthentication.BindingStatus.UNBOUND);}
 }
}