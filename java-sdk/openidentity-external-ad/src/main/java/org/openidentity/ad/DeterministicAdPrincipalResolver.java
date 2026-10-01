package org.openidentity.ad;
import java.util.*;
public final class DeterministicAdPrincipalResolver implements AdPrincipalResolver {
 public record Entry(String profileId,String authenticatedPrincipal,byte[] directoryId,byte[] objectGuid,boolean accountUsable,boolean assuranceSufficient,Map<String,Object> attributes){
  public Entry{directoryId=directoryId.clone();objectGuid=objectGuid.clone();attributes=attributes==null?Map.of():Map.copyOf(attributes);}
 }
 private final Map<String,Entry> entries;
 public DeterministicAdPrincipalResolver(Collection<Entry> entries){Map<String,Entry> m=new HashMap<>();for(var e:entries){if(e.directoryId().length!=16||e.objectGuid().length!=16)throw new IllegalArgumentException("identifier length");if(m.put(key(e.profileId(),e.authenticatedPrincipal()),e)!=null)throw new IllegalArgumentException("duplicate simulated principal");}this.entries=Map.copyOf(m);}
 @Override public VerifiedAdPrincipal resolve(AdAuthenticationEvidence e){var x=entries.get(key(e.providerProfileId(),e.authenticatedPrincipal()));if(x==null)throw new ExternalAdBindingException(ExternalAdBindingError.AD_PRINCIPAL_INVALID);return new VerifiedAdPrincipal(x.directoryId(),x.objectGuid(),e.serviceId(),e.authenticationMechanism(),e.channelTrusted(),x.accountUsable(),x.assuranceSufficient(),x.attributes());}
 private static String key(String p,String a){return p+"\u0000"+a;}
}