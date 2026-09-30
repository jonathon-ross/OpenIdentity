package org.openidentity.oauth;
public final class ProfileException extends RuntimeException {
 private final ProfileError error;
 public ProfileException(ProfileError error){super(error.name());this.error=error;}
 public ProfileException(ProfileError error,Throwable cause){super(error.name(),cause);this.error=error;}
 public ProfileError error(){return error;}
}
