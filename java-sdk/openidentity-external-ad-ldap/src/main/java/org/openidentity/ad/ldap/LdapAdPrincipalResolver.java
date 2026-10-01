package org.openidentity.ad.ldap;
import com.unboundid.ldap.sdk.*;import org.openidentity.ad.*;import java.util.*;

public final class LdapAdPrincipalResolver implements AdPrincipalResolver {
 public record Profile(String profileId,String host,int port,String baseDn,String bindDn,String bindPassword,byte[] directoryId,boolean tlsRequired){
  public Profile{if(profileId==null||profileId.isBlank()||host==null||host.isBlank()||baseDn==null||baseDn.isBlank()||bindDn==null||bindPassword==null)throw new IllegalArgumentException("profile");if(directoryId==null||directoryId.length!=16)throw new IllegalArgumentException("directoryId");directoryId=directoryId.clone();}
  @Override public byte[] directoryId(){return directoryId.clone();}
 }
 private final Profile profile;
 public LdapAdPrincipalResolver(Profile profile){this.profile=Objects.requireNonNull(profile);}
 @Override public VerifiedAdPrincipal resolve(AdAuthenticationEvidence evidence){
  if(!profile.profileId().equals(evidence.providerProfileId()))throw new ExternalAdBindingException(ExternalAdBindingError.AD_DIRECTORY_UNTRUSTED);
  if(profile.tlsRequired()&&!evidence.channelTrusted())throw new ExternalAdBindingException(ExternalAdBindingError.AD_CHANNEL_UNTRUSTED);
  try(LDAPConnection c=new LDAPConnection(profile.host(),profile.port(),profile.bindDn(),profile.bindPassword())){
   Filter f=Filter.createEqualityFilter("userPrincipalName",evidence.authenticatedPrincipal());
   SearchResult r=c.search(profile.baseDn(),SearchScope.SUB,f,"objectGUID","userAccountControl","distinguishedName","userPrincipalName");
   if(r.getEntryCount()!=1)throw new ExternalAdBindingException(ExternalAdBindingError.AD_PRINCIPAL_INVALID);
   SearchResultEntry e=r.getSearchEntries().get(0);Attribute g=attributeIgnoreCase(e,"objectGUID");if(g==null||g.getValueByteArrays().length!=1||g.getValueByteArrays()[0].length!=16)throw new ExternalAdBindingException(ExternalAdBindingError.AD_PRINCIPAL_INVALID);
   byte[] guid=g.getValueByteArrays()[0];boolean usable=true;String uac=valueIgnoreCase(e,"userAccountControl");if(uac!=null){try{usable=(Integer.parseInt(uac)&2)==0;}catch(NumberFormatException x){usable=false;}}
   return new VerifiedAdPrincipal(profile.directoryId(),guid,evidence.serviceId(),evidence.authenticationMechanism(),evidence.channelTrusted(),usable,true,Map.of("dn",e.getDN(),"upn",Objects.toString(valueIgnoreCase(e,"userPrincipalName"),"")));
  }catch(ExternalAdBindingException e){throw e;}catch(LDAPException e){throw new LdapAdResolutionException(e.getResultCode().intValue(),e.getDiagnosticMessage(),e);}
 }
 private static Attribute attributeIgnoreCase(SearchResultEntry e,String name){
  for(Attribute a:e.getAttributes())if(a.getName().equalsIgnoreCase(name))return a;
  return null;
 }
 private static String valueIgnoreCase(SearchResultEntry e,String name){
  Attribute a=attributeIgnoreCase(e,name);
  return a==null?null:a.getValue();
 }
}