package org.openidentity.oidc;

import java.util.*;
import static org.openidentity.oidc.ExternalOidcBindingError.*;

public final class InMemoryExternalOidcBindingRegistry {
 public enum Status{ACTIVE,REVOKED}
 public record State(ExternalOidcBindingV1.Binding binding,byte[] bindingId,Status status,Long revokedAt){
  public State{bindingId=bindingId.clone();}@Override public byte[] bindingId(){return bindingId.clone();}
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
  if(existing!=null&&!Arrays.equals(existing.binding().identity(),identity))fail(BINDING_CONFLICT);
  byte[] id=ExternalOidcBindingV1.bindingId(binding);State state=new State(binding,id,Status.ACTIVE,null);
  active.put(key,state);byId.put(HexFormat.of().formatHex(id),state);consumedChallenges.add(challengeKey);return state;
 }

 public synchronized State revoke(byte[] bindingId,byte[] challenge,long revokedAt,Authorization auth,Policy policy){
  State state=byId.get(HexFormat.of().formatHex(bindingId));require(state!=null,BINDING_NOT_FOUND);require(state.status()==Status.ACTIVE,BINDING_REVOKED);
  require(Arrays.equals(ExternalOidcBindingV1.bindingId(state.binding()),state.bindingId()),BINDING_ID_MISMATCH);
  require(policy.identityActive(state.binding().identity()),IDENTITY_INACTIVE);
  String ck=HexFormat.of().formatHex(challenge);require(!consumedChallenges.contains(ck),BINDING_CHALLENGE_INVALID);
  require(auth.valid()&&"openidentity.external-oidc.revoke".equals(auth.purpose()),BINDING_AUTHORIZATION_INVALID);
  require(auth.contextMatches(),BINDING_CONTEXT_MISMATCH);require(!auth.replayed(),BINDING_REPLAY);
  require(policy.currentAuthenticationGeneration(state.binding().identity())==state.binding().authenticationGeneration(),BINDING_GENERATION_STALE);
  State revoked=new State(state.binding(),state.bindingId(),Status.REVOKED,revokedAt);byId.put(HexFormat.of().formatHex(bindingId),revoked);
  active.remove(new Key(state.binding().issuer(),state.binding().subject()));consumedChallenges.add(ck);return revoked;
 }

 public synchronized ResolvedExternalOidcAuthentication resolve(VerifiedExternalOidcPrincipal principal,long now,Policy policy){
  require(policy.providerTrusted(principal.issuer()),OIDC_PROVIDER_UNTRUSTED);
  State state=active.get(new Key(principal.issuer(),principal.subject()));
  if(state==null){
   boolean revoked=byId.values().stream().anyMatch(s->s.status()==Status.REVOKED&&s.binding().issuer().equals(principal.issuer())&&s.binding().subject().equals(principal.subject()));
   if(revoked)fail(BINDING_REVOKED);fail(BINDING_NOT_FOUND);
  }
  require(Arrays.equals(ExternalOidcBindingV1.bindingId(state.binding()),state.bindingId()),BINDING_ID_MISMATCH);
  require(policy.identityActive(state.binding().identity()),IDENTITY_INACTIVE);
  require(policy.currentAuthenticationGeneration(state.binding().identity())==state.binding().authenticationGeneration(),BINDING_GENERATION_STALE);
  require(state.binding().expiresAt()==null||now<state.binding().expiresAt(),BINDING_EXPIRED);
  require(policy.clientAllowed(principal.issuer(),principal.clientId()),OIDC_CLIENT_NOT_ALLOWED);
  require(policy.assuranceSufficient(principal),ASSURANCE_INSUFFICIENT);
  return new ResolvedExternalOidcAuthentication(state.binding().identity(),state.bindingId(),principal.issuer(),principal.subject(),principal.clientId(),principal.authenticatedAt(),principal.acr(),principal.amr(),principal.providerAssurance());
 }
 private static void require(boolean ok,ExternalOidcBindingError e){if(!ok)fail(e);}private static void fail(ExternalOidcBindingError e){throw new ExternalOidcBindingException(e);}
}
