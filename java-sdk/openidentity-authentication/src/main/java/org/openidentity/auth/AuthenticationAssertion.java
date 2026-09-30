package org.openidentity.auth;
public record AuthenticationAssertion(int version,byte[] identity,byte[] stateHash,long authenticationGeneration,byte[] audience,
 String purpose,long issuedAt,long expiresAt,byte[] nonce,byte[] contextHash,byte[] exactAssertionBytes){
 public AuthenticationAssertion{identity=identity.clone();stateHash=stateHash.clone();audience=audience.clone();nonce=nonce.clone();contextHash=contextHash.clone();exactAssertionBytes=exactAssertionBytes.clone();}
}
