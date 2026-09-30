package org.openidentity.delegation;
public record ProfilePrincipal(byte[] principalId,byte[] profileHash) implements Principal {
 public ProfilePrincipal{principalId=principalId.clone();profileHash=profileHash.clone();}
}
