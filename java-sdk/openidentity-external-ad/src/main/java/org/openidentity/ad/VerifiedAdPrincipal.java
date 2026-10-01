package org.openidentity.ad;
import java.util.*;
public record VerifiedAdPrincipal(byte[] directoryId,byte[] objectGuid,String serviceId,int authenticationMechanism,boolean channelTrusted,boolean accountUsable,boolean assuranceSufficient,Map<String,Object> attributes){
 public VerifiedAdPrincipal{directoryId=copy(directoryId,16,"directoryId");objectGuid=copy(objectGuid,16,"objectGuid");if(serviceId==null||serviceId.isBlank())throw new IllegalArgumentException("serviceId");if(authenticationMechanism<1||authenticationMechanism>3)throw new IllegalArgumentException("authenticationMechanism");attributes=attributes==null?Map.of():Map.copyOf(attributes);}
 @Override public byte[] directoryId(){return directoryId.clone();}@Override public byte[] objectGuid(){return objectGuid.clone();}
 private static byte[] copy(byte[] b,int n,String name){if(b==null||b.length!=n)throw new IllegalArgumentException(name);return b.clone();}
}