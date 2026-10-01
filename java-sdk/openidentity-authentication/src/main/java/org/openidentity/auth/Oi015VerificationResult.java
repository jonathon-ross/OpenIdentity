package org.openidentity.auth;
import org.openidentity.core.VerificationError;
public record Oi015VerificationResult(boolean valid,boolean contextMismatch,byte[] identity,VerificationError error){
 public Oi015VerificationResult{identity=identity==null?null:identity.clone();}
 public Oi015VerificationResult(boolean valid,boolean contextMismatch,byte[] identity){this(valid,contextMismatch,identity,null);}
 @Override public byte[] identity(){return identity==null?null:identity.clone();}
}