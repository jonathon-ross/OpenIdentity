package org.openidentity.credentials;

import java.util.*;

public final class W3cProjectionValidator {
  private W3cProjectionValidator() {}

  public static boolean validateBasicV1(
      Map<String, Object> projection, OpenIdentityCredential credential, byte[] securedCredential) {
    Objects.requireNonNull(projection);
    Objects.requireNonNull(credential);
    Objects.requireNonNull(securedCredential);
    if (projection.containsKey("proof")) return false;
    Map<String, Object> expected;
    try {
      expected = W3cCredentialProjection.basicV1(credential, securedCredential);
    } catch (RuntimeException e) {
      return false;
    }
    return expected.equals(projection);
  }
}
