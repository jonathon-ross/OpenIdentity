package org.openidentity.oauth;
@FunctionalInterface public interface AssertionReplayStore {
 /** Atomically returns true only for the first successful consumption of assertionId. */
 boolean consume(byte[] assertionId);
}
