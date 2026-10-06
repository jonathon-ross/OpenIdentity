package org.openidentity.core;

import java.util.*;

final class Policies {
  private Policies() {}

  static List<VerificationMethod> canonicalMethods(List<VerificationMethod> methods) {
    Objects.requireNonNull(methods, "methods");
    if (methods.isEmpty())
      throw new IllegalArgumentException("Policy must contain at least one method");
    ArrayList<VerificationMethod> copy = new ArrayList<>(methods);
    if (copy.stream().anyMatch(Objects::isNull))
      throw new NullPointerException("Policy methods must not contain null");
    copy.sort(null);
    HashSet<VerificationMethodId> ids = new HashSet<>();
    for (VerificationMethod method : copy)
      if (!ids.add(method.id()))
        throw new IllegalArgumentException("Duplicate Verification Method ID: " + method.id());
    return List.copyOf(copy);
  }

  static int validateThreshold(int threshold, int methodCount) {
    if (threshold < 1 || threshold > 65535 || threshold > methodCount)
      throw new IllegalArgumentException("Invalid policy threshold: " + threshold);
    return threshold;
  }
}
