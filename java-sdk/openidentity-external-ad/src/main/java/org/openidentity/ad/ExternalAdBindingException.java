package org.openidentity.ad;
public final class ExternalAdBindingException extends RuntimeException {
 private final ExternalAdBindingError error;
 public ExternalAdBindingException(ExternalAdBindingError error){super(error.name());this.error=error;}
 public ExternalAdBindingError error(){return error;}
}