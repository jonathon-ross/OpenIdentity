package org.openidentity.spring.auth;
public interface OpenIdentityAuthenticationContinuationStore {
 void put(String challengeId,String requestTarget);
 String consume(String challengeId);
}