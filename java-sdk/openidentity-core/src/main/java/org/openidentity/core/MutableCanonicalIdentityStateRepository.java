package org.openidentity.core;
public interface MutableCanonicalIdentityStateRepository extends CanonicalIdentityStateRepository {
 void save(CanonicalIdentityState state);
}