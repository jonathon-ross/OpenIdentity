package org.openidentity.spring.oidc;

import org.openidentity.oidc.VerifiedExternalOidcPrincipal;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import java.time.Instant;
import java.util.*;

public final class SpringOidcPrincipalMapper {
 public VerifiedExternalOidcPrincipal map(OidcUser user,ClientRegistration registration){
  Objects.requireNonNull(user,"user");Objects.requireNonNull(registration,"registration");
  String issuer=required(user.getIssuer()==null?null:user.getIssuer().toString(),"iss");
  String subject=required(user.getSubject(),"sub");
  String clientId=required(registration.getClientId(),"clientId");
  Long authenticatedAt=user.getAuthenticationInstant()==null?null:user.getAuthenticationInstant().getEpochSecond();
  String acr=user.getAuthenticationContextClass()==null?null:user.getAuthenticationContextClass().getValue();
  List<String> amr=user.getAuthenticationMethods()==null?List.of():List.copyOf(user.getAuthenticationMethods());
  Map<String,Object> provider=new LinkedHashMap<>();
  Set<String> core=Set.of("iss","sub","aud","exp","iat","auth_time","nonce","acr","amr","azp");
  user.getClaims().forEach((k,v)->{if(!core.contains(k))provider.put(k,v);});
  return new VerifiedExternalOidcPrincipal(issuer,subject,clientId,authenticatedAt,acr,amr,provider);
 }
 private static String required(String v,String name){if(v==null||v.isBlank())throw new IllegalArgumentException(name);return v;}
}
