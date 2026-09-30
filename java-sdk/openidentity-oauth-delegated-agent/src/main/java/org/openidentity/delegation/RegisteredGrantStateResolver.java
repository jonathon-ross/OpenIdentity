package org.openidentity.delegation;
@FunctionalInterface public interface RegisteredGrantStateResolver { RegisteredGrantState resolve(byte[] registryDomain,byte[] grantId); }
