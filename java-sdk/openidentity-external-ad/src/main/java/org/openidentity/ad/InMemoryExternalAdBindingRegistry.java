package org.openidentity.ad;
import java.util.*;
import static org.openidentity.ad.ExternalAdBindingError.*;

public final class InMemoryExternalAdBindingRegistry {
 public enum Status{ACTIVE,REVOKED}
 public record Principal(byte[] directoryId,byte[] objectGuid,String serviceId,int mechanism,boolean channelTrusted,boolean accountUsable,boolean assuranceSufficient){
  public Principal{directoryId=copy(directoryId,16,"directoryId");objectGuid=copy(objectGuid,16,"objectGuid");if(serviceId==null||serviceId.isEmpty())throw new IllegalArgumentException("serviceId");}
  @Override public byte[] directoryId(){return directoryId.clone();}@Override public byte[] objectGuid(){return objectGuid.clone();}
 }
 public record Authorization(boolean valid,String purpose,boolean contextMatches,boolean replayed){}
 public interface Policy{boolean directoryTrusted(byte[] directoryId);boolean serviceAllowed(byte[] directoryId,String serviceId);boolean mechanismAllowed(byte[] directoryId,int mechanism);boolean identityActive(byte[] identity);long currentAuthenticationGeneration(byte[] identity);}
 public record State(byte[] bindingBytes,byte[] bindingId,Status status,Long revokedAt){public State{bindingBytes=bindingBytes.clone();bindingId=bindingId.clone();}@Override public byte[] bindingBytes(){return bindingBytes.clone();}@Override public byte[] bindingId(){return bindingId.clone();}}
 public record Resolved(byte[] identity,byte[] bindingId){public Resolved{identity=identity.clone();bindingId=bindingId.clone();}@Override public byte[] identity(){return identity.clone();}@Override public byte[] bindingId(){return bindingId.clone();}}
 private record Key(String directory,String guid){}
 private final Map<Key,State> active=new HashMap<>();private final Map<Key,State> terminal=new HashMap<>();private final Map<String,State> byId=new HashMap<>();private final Set<String> consumed=new HashSet<>();
 public State bind(Principal p,byte[] identity,long now,Long expires,byte[] challenge,Authorization a,Policy policy){
  validatePrincipal(p,policy);if(identity==null||identity.length!=32)fail(AD_PRINCIPAL_INVALID);if(!policy.identityActive(identity))fail(IDENTITY_INACTIVE);auth(a,"openidentity.external-ad.bind");String ck=hex(challenge);if(!consumed.add(ck))fail(BINDING_CHALLENGE_INVALID);
  var b=new ExternalAdBindingV1.Binding(identity,p.directoryId(),p.objectGuid(),p.serviceId(),now,expires,policy.currentAuthenticationGeneration(identity));byte[] bytes=ExternalAdBindingV1.encode(b),id=ExternalAdBindingV1.bindingId(b);Key k=key(p);State old=active.get(k);if(old!=null){var ob=verified(old);if(!Arrays.equals(ob.identity(),identity))fail(BINDING_CONFLICT);return old;}
  State s=new State(bytes,id,Status.ACTIVE,null);active.put(k,s);byId.put(hex(id),s);return s;
 }
 public Resolved resolve(Principal p,long now,Policy policy){validatePrincipal(p,policy);Key k=key(p);State s=active.get(k);if(s==null){s=terminal.get(k);if(s==null)fail(BINDING_NOT_FOUND);}var b=verified(s);if(s.status()==Status.REVOKED)fail(BINDING_REVOKED);if(b.expiresAt()!=null&&now>=b.expiresAt())fail(BINDING_EXPIRED);if(!policy.identityActive(b.identity()))fail(IDENTITY_INACTIVE);if(policy.currentAuthenticationGeneration(b.identity())!=b.authenticationGeneration())fail(BINDING_GENERATION_STALE);return new Resolved(b.identity(),s.bindingId());}
 public State revoke(byte[] bindingId,byte[] challenge,long now,Authorization a,Policy policy){State s=byId.get(hex(bindingId));if(s==null)fail(BINDING_NOT_FOUND);var b=verified(s);auth(a,"openidentity.external-ad.revoke");String ck=hex(challenge);if(!consumed.add(ck))fail(BINDING_CHALLENGE_INVALID);State r=new State(s.bindingBytes(),s.bindingId(),Status.REVOKED,now);byId.put(hex(bindingId),r);Key k=new Key(hex(b.directoryId()),hex(b.objectGuid()));active.remove(k);terminal.put(k,r);return r;}
 void replaceStateForTest(State s){byId.put(hex(s.bindingId()),s);var b=verified(s);if(s.status()==Status.ACTIVE)active.put(new Key(hex(b.directoryId()),hex(b.objectGuid())),s);}
 private static ExternalAdBindingV1.Binding verified(State s){var b=ExternalAdBindingV1.decode(s.bindingBytes());if(!Arrays.equals(ExternalAdBindingV1.bindingId(b),s.bindingId()))fail(BINDING_ID_MISMATCH);return b;}
 private static void validatePrincipal(Principal p,Policy policy){if(!policy.directoryTrusted(p.directoryId()))fail(AD_DIRECTORY_UNTRUSTED);if(!policy.serviceAllowed(p.directoryId(),p.serviceId()))fail(AD_SERVICE_NOT_ALLOWED);if(!policy.mechanismAllowed(p.directoryId(),p.mechanism()))fail(AD_AUTH_MECHANISM_NOT_ALLOWED);if(!p.channelTrusted())fail(AD_CHANNEL_UNTRUSTED);if(!p.accountUsable())fail(AD_ACCOUNT_UNUSABLE);if(!p.assuranceSufficient())fail(ASSURANCE_INSUFFICIENT);}
 private static void auth(Authorization a,String purpose){if(a==null||!a.valid()||!purpose.equals(a.purpose()))fail(BINDING_AUTHORIZATION_INVALID);if(!a.contextMatches())fail(BINDING_CONTEXT_MISMATCH);if(a.replayed())fail(BINDING_REPLAY);}
 private static Key key(Principal p){return new Key(hex(p.directoryId()),hex(p.objectGuid()));}private static String hex(byte[] b){return HexFormat.of().formatHex(b);}private static byte[] copy(byte[] b,int n,String x){if(b==null||b.length!=n)throw new IllegalArgumentException(x);return b.clone();}private static void fail(ExternalAdBindingError e){throw new ExternalAdBindingException(e);}
}