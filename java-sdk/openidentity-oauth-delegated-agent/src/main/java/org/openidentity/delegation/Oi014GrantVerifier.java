package org.openidentity.delegation;
import org.openidentity.oauth.ProfileException;
@FunctionalInterface public interface Oi014GrantVerifier {
 /** Verifies exact frozen GrantBytes against authoritative current OI-014 state and returns current use-time facts. */
 VerifiedGrant verify(byte[] registryDomain,byte[] exactGrantBytes,long verificationTime) throws ProfileException;
}
