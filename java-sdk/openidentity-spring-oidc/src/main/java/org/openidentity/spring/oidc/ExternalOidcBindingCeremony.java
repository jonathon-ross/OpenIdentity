package org.openidentity.spring.oidc;

import org.openidentity.auth.*;
import org.openidentity.oidc.*;
import java.security.SecureRandom;
import java.util.*;

public final class ExternalOidcBindingCeremony {
 public static final String BIND_PURPOSE="openidentity.external-oidc.bind";
 public record Pending(byte[] identity,VerifiedExternalOidcPrincipal principal,long generation,long createdAt,Long expiresAt,byte[] challenge,byte[] contextBytes,byte[] contextHash){
  public Pending{identity=identity.clone();challenge=challenge.clone();contextBytes=contextBytes.clone();contextHash=contextHash.clone();}
  @Override public byte[] identity(){return identity.clone();}@Override public byte[] challenge(){return challenge.clone();}@Override public byte[] contextBytes(){return contextBytes.clone();}@Override public byte[] contextHash(){return contextHash.clone();}
 }
 private final Oi015Verifier verifier;private final InMemoryExternalOidcBindingRegistry registry;private final InMemoryExternalOidcBindingRegistry.Policy policy;private final SecureRandom random;
 public ExternalOidcBindingCeremony(Oi015Verifier verifier,InMemoryExternalOidcBindingRegistry registry,InMemoryExternalOidcBindingRegistry.Policy policy){this(verifier,registry,policy,new SecureRandom());}
 ExternalOidcBindingCeremony(Oi015Verifier verifier,InMemoryExternalOidcBindingRegistry registry,InMemoryExternalOidcBindingRegistry.Policy policy,SecureRandom random){this.verifier=Objects.requireNonNull(verifier);this.registry=Objects.requireNonNull(registry);this.policy=Objects.requireNonNull(policy);this.random=Objects.requireNonNull(random);}

 public Pending begin(VerifiedExternalOidcPrincipal principal,byte[] identity,long createdAt,Long expiresAt){
  Objects.requireNonNull(principal);Objects.requireNonNull(identity);long generation=policy.currentAuthenticationGeneration(identity);
  byte[] challenge=new byte[32];random.nextBytes(challenge);
  var binding=new ExternalOidcBindingV1.Binding(identity,principal.issuer(),principal.subject(),principal.clientId(),createdAt,expiresAt,generation);
  byte[] context=ExternalOidcBindingV1.encodeContext(1,binding,challenge,null);
  return new Pending(identity,principal,generation,createdAt,expiresAt,challenge,context,ExternalOidcBindingV1.contextHash(context));
 }

 public InMemoryExternalOidcBindingRegistry.State complete(Pending pending,SecuredAuthenticationAssertion assertion,byte[] audience,byte[] oi015Nonce,long now){
  Objects.requireNonNull(pending);Objects.requireNonNull(assertion);
  Oi015VerificationResult verified=verifier.tryVerify(assertion,audience,BIND_PURPOSE,oi015Nonce,pending.contextHash(),now);
  if(!verified.valid())throw new ExternalOidcBindingException(verified.contextMismatch()?ExternalOidcBindingError.BINDING_CONTEXT_MISMATCH:ExternalOidcBindingError.BINDING_AUTHORIZATION_INVALID);
  if(!java.security.MessageDigest.isEqual(verified.identity(),pending.identity()))throw new ExternalOidcBindingException(ExternalOidcBindingError.BINDING_AUTHORIZATION_INVALID);
  if(policy.currentAuthenticationGeneration(pending.identity())!=pending.generation())throw new ExternalOidcBindingException(ExternalOidcBindingError.BINDING_GENERATION_STALE);
  return registry.bind(pending.principal(),pending.identity(),pending.createdAt(),pending.expiresAt(),pending.challenge(),new InMemoryExternalOidcBindingRegistry.Authorization(true,BIND_PURPOSE,true,false),policy);
 }
}
