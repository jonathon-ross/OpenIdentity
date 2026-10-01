package org.openidentity.spring.oidc.entra;

import org.openidentity.oidc.VerifiedExternalOidcPrincipal;
import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

public final class EntraOidcProfile {
 private static final Pattern GUID=Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
 private final String tenantId;private final Set<String> allowedClientIds;
 public EntraOidcProfile(String tenantId,Collection<String> allowedClientIds){
  if(tenantId==null||!GUID.matcher(tenantId).matches())throw new IllegalArgumentException("tenantId must be GUID");
  this.tenantId=tenantId.toLowerCase(Locale.ROOT);this.allowedClientIds=Set.copyOf(allowedClientIds);
  if(this.allowedClientIds.isEmpty())throw new IllegalArgumentException("allowedClientIds");
 }
 public String tenantId(){return tenantId;}
 public String issuer(){return "https://login.microsoftonline.com/"+tenantId+"/v2.0";}
 public String issuerUri(){return issuer();}
 public boolean providerTrusted(String issuer){return issuer().equals(issuer);}
 public boolean clientAllowed(String issuer,String clientId){return providerTrusted(issuer)&&allowedClientIds.contains(clientId);}
 public void validate(VerifiedExternalOidcPrincipal principal){
  if(!providerTrusted(principal.issuer()))throw new IllegalArgumentException("issuer");
  if(!clientAllowed(principal.issuer(),principal.clientId()))throw new IllegalArgumentException("clientId");
  Object tid=principal.providerAssurance().get("tid");
  if(!(tid instanceof String s)||!GUID.matcher(s).matches()||!tenantId.equals(s.toLowerCase(Locale.ROOT)))throw new IllegalArgumentException("tid");
 }
 public Map<String,Object> normalizedAssurance(VerifiedExternalOidcPrincipal principal){
  validate(principal);Map<String,Object> out=new LinkedHashMap<>();
  copy(principal.providerAssurance(),out,"tid","oid","preferred_username","name","idp","sid","ver","roles","groups","hasgroups","xms_cc");
  return Collections.unmodifiableMap(out);
 }
 private static void copy(Map<String,Object> from,Map<String,Object> to,String... keys){for(String k:keys)if(from.containsKey(k))to.put(k,from.get(k));}
}
