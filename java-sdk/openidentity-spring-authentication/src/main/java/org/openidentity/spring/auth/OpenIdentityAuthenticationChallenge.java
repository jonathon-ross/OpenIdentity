package org.openidentity.spring.auth;
public record OpenIdentityAuthenticationChallenge(byte[] audience,String purpose,byte[] nonce,byte[] contextHash,long issuedAt,long expiresAt){
 public OpenIdentityAuthenticationChallenge{audience=audience.clone();nonce=nonce.clone();contextHash=contextHash.clone();}
 @Override public byte[] audience(){return audience.clone();}@Override public byte[] nonce(){return nonce.clone();}@Override public byte[] contextHash(){return contextHash.clone();}
}