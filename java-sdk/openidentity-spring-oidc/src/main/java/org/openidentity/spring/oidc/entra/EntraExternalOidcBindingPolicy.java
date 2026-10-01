package org.openidentity.spring.oidc.entra;

import org.openidentity.oidc.*;
import java.util.Objects;
import java.util.function.*;

public final class EntraExternalOidcBindingPolicy implements InMemoryExternalOidcBindingRegistry.Policy {
 private final EntraOidcProfile profile;private final Predicate<byte[]> identityActive;private final ToLongFunction<byte[]> generation;private final Predicate<VerifiedExternalOidcPrincipal> assurance;
 public EntraExternalOidcBindingPolicy(EntraOidcProfile profile,Predicate<byte[]> identityActive,ToLongFunction<byte[]> generation,Predicate<VerifiedExternalOidcPrincipal> assurance){
  this.profile=Objects.requireNonNull(profile);this.identityActive=Objects.requireNonNull(identityActive);this.generation=Objects.requireNonNull(generation);this.assurance=Objects.requireNonNull(assurance);
 }
 public boolean providerTrusted(String issuer){return profile.providerTrusted(issuer);}
 public boolean clientAllowed(String issuer,String clientId){return profile.clientAllowed(issuer,clientId);}
 public boolean identityActive(byte[] identity){return identityActive.test(identity);}
 public long currentAuthenticationGeneration(byte[] identity){return generation.applyAsLong(identity);}
 public boolean assuranceSufficient(VerifiedExternalOidcPrincipal principal){try{profile.validate(principal);return assurance.test(principal);}catch(IllegalArgumentException e){return false;}}
}
