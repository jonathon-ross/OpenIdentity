package org.openidentity.oauth;
public record VerifiedAuthenticationAssertion(byte[] identity,byte[] assertionId,byte[] contextHash,String purpose){
 public VerifiedAuthenticationAssertion{identity=identity.clone();assertionId=assertionId.clone();contextHash=contextHash.clone();}
}
