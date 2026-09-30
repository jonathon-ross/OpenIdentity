package org.openidentity.delegation;
@FunctionalInterface public interface RootDelegationStateResolver { RootDelegationState resolve(byte[] rootGrantor); }
