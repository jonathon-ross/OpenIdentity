package org.openidentity.delegation;
import java.util.List;
public record DelegationGrant(byte[] exactBytes,byte[] grantId,byte[] rootGrantor,Principal issuer,Principal delegate,List<CapabilityRef> capabilities,Long notBefore,long expiresAt,byte[] parentGrantId,byte[] nonce){
 public DelegationGrant{exactBytes=exactBytes.clone();grantId=grantId.clone();rootGrantor=rootGrantor.clone();capabilities=List.copyOf(capabilities);parentGrantId=parentGrantId==null?null:parentGrantId.clone();nonce=nonce.clone();}
}
