package org.openidentity.oidc;
import java.util.List;import java.util.Map;import java.util.Objects;
public record VerifiedExternalOidcPrincipal(String issuer,String subject,String clientId,Long authenticatedAt,String acr,List<String> amr,Map<String,Object> providerAssurance){
 public VerifiedExternalOidcPrincipal{Objects.requireNonNull(issuer);Objects.requireNonNull(subject);Objects.requireNonNull(clientId);amr=List.copyOf(amr==null?List.of():amr);providerAssurance=Map.copyOf(providerAssurance==null?Map.of():providerAssurance);}
}