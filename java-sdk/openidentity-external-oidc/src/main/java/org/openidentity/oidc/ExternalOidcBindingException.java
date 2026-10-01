package org.openidentity.oidc;
public final class ExternalOidcBindingException extends RuntimeException {
 private final ExternalOidcBindingError error;
 public ExternalOidcBindingException(ExternalOidcBindingError error){super(error.name());this.error=error;}
 public ExternalOidcBindingError error(){return error;}
}