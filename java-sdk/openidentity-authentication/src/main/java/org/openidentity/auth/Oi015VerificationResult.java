package org.openidentity.auth;
public record Oi015VerificationResult(boolean valid,boolean contextMismatch,byte[] identity){
 public Oi015VerificationResult{identity=identity==null?null:identity.clone();}
 @Override public byte[] identity(){return identity==null?null:identity.clone();}
}