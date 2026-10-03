package org.openidentity.core;

/**
 * Protocol-version-specific verification boundary for authoritative state
 * transitions. Implementations MUST fail closed and return a result only after
 * validating the complete OpenIdentity operation and deriving exact successor
 * StateBytes.
 */
@FunctionalInterface
public interface IdentityTransitionVerifier {
    VerifiedIdentityTransition verify(byte[] predecessorStateBytes, byte[] signedOperationBytes);
}
