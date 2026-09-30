package org.openidentity.core;
public record VerifiedAuthentication(byte[] identity,byte[] assertionId,byte[] contextHash,String purpose){
 public VerifiedAuthentication{identity=identity.clone();assertionId=assertionId.clone();contextHash=contextHash.clone();}
 @Override public byte[] identity(){return identity.clone();}@Override public byte[] assertionId(){return assertionId.clone();}@Override public byte[] contextHash(){return contextHash.clone();}
}
