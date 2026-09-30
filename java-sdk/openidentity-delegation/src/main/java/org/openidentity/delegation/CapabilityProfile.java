package org.openidentity.delegation;
import java.util.List;
public interface CapabilityProfile {
 byte[] profileHash();
 long maximumGrantLifetimeSeconds();
 int maximumDelegationDepth();
 /** True iff child capabilities/resources are a permitted attenuation of parent authority. */
 boolean permitsChild(List<CapabilityRef> parent,List<CapabilityRef> child);
 /** Profile-owned effective capability representation consumed by OAuth CapabilityMapper. */
 List<Object> effectiveCapabilities(List<CapabilityRef> capabilities);
}
