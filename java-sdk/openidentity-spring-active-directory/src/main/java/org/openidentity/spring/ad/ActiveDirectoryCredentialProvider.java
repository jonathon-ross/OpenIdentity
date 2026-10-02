package org.openidentity.spring.ad;
@FunctionalInterface
public interface ActiveDirectoryCredentialProvider {
 String ldapBindPassword();
}