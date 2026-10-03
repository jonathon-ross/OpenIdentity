package org.openidentity.spring.auth;
public interface OpenIdentityAuthenticationChallengeStore {
 String create(OpenIdentityAuthenticationChallenge challenge);
 OpenIdentityAuthenticationChallenge consume(String challengeId);
}