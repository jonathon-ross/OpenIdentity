package org.openidentity.core;
public interface CanonicalIdentityStateRepository {
 CanonicalIdentityState resolve(byte[] identity);
}