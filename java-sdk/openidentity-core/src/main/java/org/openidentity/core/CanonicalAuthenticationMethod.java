package org.openidentity.core;
public record CanonicalAuthenticationMethod(byte[] methodId,byte[] ed25519PublicKey){
 public CanonicalAuthenticationMethod{methodId=methodId.clone();ed25519PublicKey=ed25519PublicKey.clone();if(methodId.length<1||methodId.length>64||ed25519PublicKey.length!=32)throw new IllegalArgumentException("authentication method");}
 @Override public byte[] methodId(){return methodId.clone();}@Override public byte[] ed25519PublicKey(){return ed25519PublicKey.clone();}
}