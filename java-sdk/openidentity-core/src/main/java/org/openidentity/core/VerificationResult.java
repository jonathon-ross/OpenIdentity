package org.openidentity.core;

import java.util.Objects;
import java.util.Optional;

/** Structured result for verification APIs that do not need to throw. */
public record VerificationResult(boolean valid, OpenIdentityError error, String detail) {
  public VerificationResult {
    if (valid && error != null)
      throw new IllegalArgumentException("Valid result cannot contain an error");
    if (!valid) Objects.requireNonNull(error, "Invalid result requires an error");
  }

  public static VerificationResult success() {
    return new VerificationResult(true, null, null);
  }

  public static VerificationResult failure(OpenIdentityError error, String detail) {
    return new VerificationResult(false, Objects.requireNonNull(error), detail);
  }

  public Optional<OpenIdentityError> errorCode() {
    return Optional.ofNullable(error);
  }

  public Optional<String> detailMessage() {
    return Optional.ofNullable(detail);
  }
}
