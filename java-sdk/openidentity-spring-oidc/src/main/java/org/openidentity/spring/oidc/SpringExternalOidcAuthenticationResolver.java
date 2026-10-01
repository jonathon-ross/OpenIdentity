package org.openidentity.spring.oidc;

import org.openidentity.oidc.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import java.util.Objects;

public final class SpringExternalOidcAuthenticationResolver {
 private final SpringOidcPrincipalMapper mapper;
 private final InMemoryExternalOidcBindingRegistry registry;
 private final InMemoryExternalOidcBindingRegistry.Policy policy;
 public SpringExternalOidcAuthenticationResolver(SpringOidcPrincipalMapper mapper,InMemoryExternalOidcBindingRegistry registry,InMemoryExternalOidcBindingRegistry.Policy policy){
  this.mapper=Objects.requireNonNull(mapper);this.registry=Objects.requireNonNull(registry);this.policy=Objects.requireNonNull(policy);
 }
 public ResolvedExternalOidcAuthentication resolve(OidcUser user,ClientRegistration registration,long now){
  return registry.resolve(mapper.map(user,registration),now,policy);
 }
}
