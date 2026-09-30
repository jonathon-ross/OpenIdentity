package org.openidentity.delegation;
@FunctionalInterface public interface CapabilityProfileResolver { CapabilityProfile resolve(byte[] profileHash); }
