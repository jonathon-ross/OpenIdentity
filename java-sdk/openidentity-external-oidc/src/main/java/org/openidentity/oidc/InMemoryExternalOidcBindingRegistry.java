package org.openidentity.oidc;

import java.util.*;
import static org.openidentity.oidc.ExternalOidcBindingError.*;

public final class InMemoryExternalOidcBindingRegistry {
 public enum Status{ACTIVE,REVOKED}
 public record State(byte[] bindingBytes,byte[] bindingId,Status status,Long revokedAt){
  public State{bindingBytes=bindingBytes.clone();bindingId=bindingId.clone();}
  @Override public byte[] bindingBytes(){return bindingBytes.clone();}@Override public byte[] bindingId(){return bindingId.clone();}
  public ExternalOidcBindingV1.Binding binding(){return ExternalOidcBindingV1.decode(bindingBytes);}
 }
 public record Authorization(boolean valid,String purpose,boolean contextMatches,boolean replayed){}
 public interface Policy{
  boolean providerTrusted(String issuer);
  boolean clientAllowed(String issuer,String clientId);
  boolean identityActive(byte[] identity);
  long currentAuthenticationGeneration(byte[] identity);
  boolean assuranceSufficient(VerifiedExternalOidcPrincipal principal);
 }

 private record Key(String issuer,String subject){}
 private final Map<Key,State> active=new HashMap<>();
 private final Map<String,State> byId=new HashMap<>();
 private final Set<String> consumedChallenges=new HashSet<>();

 public synchronized State bind(VerifiedExternalOidcPrincipal principal,byte[] identity,long createdAt,Long expiresAt,byte[] challenge,Authorization auth,Policy policy){
  require(policy.providerTrusted(principal.issuer()),OIDC_PROVIDER_UNTRUSTED);
  require(!principal.issuer().isEmpty()&&!principal.subject().isEmpty(),OIDC_PRINCIPAL_INVALID);
  require(policy.clientAllowed(principal.issuer(),principal.clientId()),OIDC_CLIENT_NOT_ALLOWED);
  String challengeKey=HexFormat.of().formatHex(challenge);require(!consumedChallenges.contains(challengeKey),BINDING_CHALLENGE_INVALID);
  require(auth.valid()&&"openidentity.external-oidc.bind".equals(auth.purpose()),BINDING_AUTHORIZATION_INVALID);
  require(auth.contextMatches(),BINDING_CONTEXT_MISMATCH);require(!auth.replayed(),BINDING_REPLAY);
  require(policy.identityActive(identity),IDENTITY_INACTIVE);
  long generation=policy.currentAuthenticationGeneration(identity);
  var binding=new ExternalOidcBindingV1.Binding(identity,principal.issuer(),principal.subject(),principal.clientId(),createdAt,expiresAt,generation);
  Key key=new Key(principal.issuer(),principal.subject());State existing=active.get(key);
  if(existing!=null&&!Arrays.equals(verified(existing).identity(),identity))fail(BINDING_CONFLICT);
  byte[] bytes=ExternalOidcBindingV1.encode(binding),id=ExternalOidcBindingV1.bindingId(bytes);State state=new State(bytes,id,Status.ACTIVE,null);
  active.put(key,state);byId.put(HexFormat.of().formatHex(id),state);consumedChallenges.add(challengeKey);return state;
 }

 public synchronized State revoke(byte[] bindingId,byte[] challenge,long revokedAt,Authorization auth,Policy policy){
  State state=byId.get(HexFormat.of().formatHex(bindingId));require(state!=null,BINDING_NOT_FOUND);require(state.status()==Status.ACTIVE,BINDING_REVOKED);
  ExternalOidcBindingV1.Binding stored=verified(state);
  require(policy.identityActive(stored.identity()),IDENTITY_INACTIVE);
  String ck=HexFormat.of().formatHex(challenge);require(!consumedChallenges.contains(ck),BINDING_CHALLENGE_INVALID);
  require(auth.valid()&&"openidentity.external-oidc.revoke".equals(auth.purpose()),BINDING_AUTHORIZATION_INVALID);
  require(auth.contextMatches(),BINDING_CONTEXT_MISMATCH);require(!auth.replayed(),BINDING_REPLAY);
  require(policy.currentAuthenticationGeneration(stored.identity())==stored.authenticationGeneration(),BINDING_GENERATION_STALE);
  State revoked=new State(state.bindingBytes(),state.bindingId(),Status.REVOKED,revokedAt);byId.put(HexFormat.of().formatHex(bindingId),revoked);
  active.remove(new Key(stored.issuer(),stored.subject()));consumedChallenges.add(ck);return revoked;
 }

 public synchronized ResolvedExternalOidcAuthentication resolve(VerifiedExternalOidcPrincipal principal,long now,Policy policy){
  require(policy.providerTrusted(principal.issuer()),OIDC_PROVIDER_UNTRUSTED);
  State state=active.get(new Key(principal.issuer(),principal.subject()));
  if(state==null){
   boolean revoked=byId.values().stream().anyMatch(s->{try{var b=verified(s);return s.status()==Status.REVOKED&&b.issuer().equals(principal.issuer())&&b.subject().equals(principal.subject());}catch(ExternalOidcBindingException e){return false;}});
   if(revoked)fail(BINDING_REVOKED);fail(BINDING_NOT_FOUND);
  }
  ExternalOidcBindingV1.Binding stored=verified(state);
  require(policy.identityActive(stored.identity()),IDENTITY_INACTIVE);
  require(policy.currentAuthenticationGeneration(stored.identity())==stored.authenticationGeneration(),BINDING_GENERATION_STALE);
  require(stored.expiresAt()==null||now<stored.expiresAt(),BINDING_EXPIRED);
  require(policy.clientAllowed(principal.issuer(),principal.clientId()),OIDC_CLIENT_NOT_ALLOWED);
  require(policy.assuranceSufficient(principal),ASSURANCE_INSUFFICIENT);
  return new ResolvedExternalOidcAuthentication(stored.identity(),state.bindingId(),principal.issuer(),principal.subject(),principal.clientId(),principal.authenticatedAt(),principal.acr(),principal.amr(),principal.providerAssurance());
 }
 private static ExternalOidcBindingV1.Binding verified(State state){
  final ExternalOidcBindingV1.Binding b;
  try{b=ExternalOidcBindingV1.decode(state.bindingBytes());}catch(IllegalArgumentException e){fail(OIDC_PRINCIPAL_INVALID);return null;}
  require(Arrays.equals(ExternalOidcBindingV1.bindingId(state.bindingBytes()),state.bindingId()),BINDING_ID_MISMATCH);return b;
 }
 // Test-only corruption hook used to exercise persisted-state integrity failures.
 synchronized void replaceStateForTest(State state){
  var b=ExternalOidcBindingV1.decode(state.bindingBytes());active.put(new Key(b.issuer(),b.subject()),state);byId.put(HexFormat.of().formatHex(state.bindingId()),state);
 }
 private static void require(boolean ok,ExternalOidcBindingError e){if(!ok)fail(e);}private static void fail(ExternalOidcBindingError e){throw new ExternalOidcBindingException(e);}
}
