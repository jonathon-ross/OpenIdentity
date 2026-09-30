package org.openidentity.oauth;
@FunctionalInterface public interface AuthenticationAssertionVerifier {
 VerifiedAuthenticationAssertion verify(byte[] exactOi015Bytes) throws ProfileException;
}
