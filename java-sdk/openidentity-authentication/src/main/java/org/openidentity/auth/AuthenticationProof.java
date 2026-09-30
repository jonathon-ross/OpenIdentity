package org.openidentity.auth;
public record AuthenticationProof(byte[] methodId,byte[] signature){
 public AuthenticationProof{methodId=methodId.clone();signature=signature.clone();}
}
