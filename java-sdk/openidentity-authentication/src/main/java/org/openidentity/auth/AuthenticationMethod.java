package org.openidentity.auth;
public record AuthenticationMethod(byte[] methodId,byte[] ed25519PublicKey){
 public AuthenticationMethod{methodId=methodId.clone();ed25519PublicKey=ed25519PublicKey.clone();if(ed25519PublicKey.length!=32)throw new IllegalArgumentException("Ed25519 public key length");}
 @Override public byte[] methodId(){return methodId.clone();}@Override public byte[] ed25519PublicKey(){return ed25519PublicKey.clone();}
}
