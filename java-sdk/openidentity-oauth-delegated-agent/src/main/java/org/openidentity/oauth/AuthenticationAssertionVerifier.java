package org.openidentity.oauth;
@FunctionalInterface public interface AuthenticationAssertionVerifier {
 VerifiedAuthenticationAssertion verify(AuthenticationVerificationRequest request) throws ProfileException;
}
