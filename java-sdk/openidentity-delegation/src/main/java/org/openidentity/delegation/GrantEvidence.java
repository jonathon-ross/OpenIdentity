package org.openidentity.delegation;
public record GrantEvidence(byte[] grantBytes,byte[] grantId){
 public GrantEvidence{grantBytes=grantBytes.clone();grantId=grantId.clone();}
 @Override public byte[] grantBytes(){return grantBytes.clone();}@Override public byte[] grantId(){return grantId.clone();}
}
