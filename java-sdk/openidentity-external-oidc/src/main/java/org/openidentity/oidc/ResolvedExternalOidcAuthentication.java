package org.openidentity.oidc;
import java.util.List;import java.util.Map;
public record ResolvedExternalOidcAuthentication(byte[] identity,byte[] bindingId,String issuer,String subject,String clientId,Long authenticatedAt,String acr,List<String> amr,Map<String,Object> providerAssurance){
 public ResolvedExternalOidcAuthentication{identity=identity.clone();bindingId=bindingId.clone();amr=List.copyOf(amr);providerAssurance=Map.copyOf(providerAssurance);}
 @Override public byte[] identity(){return identity.clone();}@Override public byte[] bindingId(){return bindingId.clone();}
}