package org.openidentity.oauth;
@FunctionalInterface public interface DelegatedSubjectVerifier {
 VerifiedDelegatedSubject verify(byte[] exactOi016Bytes) throws ProfileException;
}
