package org.openidentity.auth;

import org.openidentity.core.*;
import java.util.*;

public final class CanonicalAuthenticationStateResolver implements AuthenticationStateResolver {
 private final CanonicalIdentityStateRepository repository;
 public CanonicalAuthenticationStateResolver(CanonicalIdentityStateRepository repository){this.repository=Objects.requireNonNull(repository);}
 @Override public CurrentAuthenticationState resolve(byte[] identity){
  CanonicalIdentityState state=repository.resolve(identity);if(state==null)return null;
  CanonicalAuthenticationAuthority a=state.authenticationAuthority();if(a==null)return null;
  List<AuthenticationMethod> methods=a.methods().stream().map(m->new AuthenticationMethod(m.methodId(),m.ed25519PublicKey())).toList();
  return new CurrentAuthenticationState(state.identity(),state.stateHash(),state.active(),new AuthenticationPolicySnapshot(a.generation(),a.threshold(),methods));
 }
}
