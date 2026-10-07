package org.openidentity.core;
public final class VerificationException extends RuntimeException {
 private final VerificationError error;
 public VerificationException(VerificationError error){super(error.name());this.error=error;}
 public VerificationException(VerificationError error,Throwable cause){super(error.name(),cause);this.error=error;}
 public VerificationError error(){return error;}
}
