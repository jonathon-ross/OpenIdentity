package org.openidentity.delegation;
import java.util.List;
public record VerifiedGrant(byte[] grantId,byte[] rootGrantor,byte[] issuer,byte[] delegate,byte[] parentGrantId,long expiresAt,List<Object> effectiveCapabilities,int maximumDelegationDepth){
 public VerifiedGrant{grantId=grantId.clone();rootGrantor=rootGrantor.clone();issuer=issuer.clone();delegate=delegate.clone();parentGrantId=parentGrantId==null?null:parentGrantId.clone();effectiveCapabilities=List.copyOf(effectiveCapabilities);}
 @Override public byte[] grantId(){return grantId.clone();}@Override public byte[] rootGrantor(){return rootGrantor.clone();}@Override public byte[] issuer(){return issuer.clone();}@Override public byte[] delegate(){return delegate.clone();}@Override public byte[] parentGrantId(){return parentGrantId==null?null:parentGrantId.clone();}
}
