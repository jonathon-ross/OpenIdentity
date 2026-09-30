package org.openidentity.oauth;
@FunctionalInterface public interface CapabilityMapper {
 boolean explicitlyAllows(VerifiedDelegatedSubject subject,String resolvedTarget,String scope);
}
