package org.openidentity.oauth;
public record AuthenticationVerificationRequest(byte[] securedAssertionBytes,byte[] expectedAudience,String expectedPurpose,byte[] expectedNonce,byte[] expectedContextHash,long verificationTime){
 public AuthenticationVerificationRequest{securedAssertionBytes=securedAssertionBytes.clone();expectedAudience=expectedAudience.clone();expectedNonce=expectedNonce.clone();expectedContextHash=expectedContextHash.clone();}
}
