package org.openidentity.core;

import java.util.Objects;

/** Protocol-aware exception for state-transition APIs. */
public class OpenIdentityException extends IllegalArgumentException {
  private final OpenIdentityError error;

  public OpenIdentityException(OpenIdentityError error, String message) {
    super(message);
    this.error = Objects.requireNonNull(error, "error");
  }

  public OpenIdentityError error() {
    return error;
  }
}
