package org.openidentity.ad;
import java.util.*;
public record AdAuthenticationEvidence(String providerProfileId,String authenticatedPrincipal,String serviceId,int authenticationMechanism,boolean channelTrusted,Map<String,Object> evidence){
 public AdAuthenticationEvidence{if(providerProfileId==null||providerProfileId.isBlank()||authenticatedPrincipal==null||authenticatedPrincipal.isBlank()||serviceId==null||serviceId.isBlank())throw new IllegalArgumentException("evidence");evidence=evidence==null?Map.of():Map.copyOf(evidence);}
}