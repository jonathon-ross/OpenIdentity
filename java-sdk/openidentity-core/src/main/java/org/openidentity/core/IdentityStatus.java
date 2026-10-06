package org.openidentity.core;

/** OpenIdentity v0.1 IdentityState status registry. */
public enum IdentityStatus {
  ACTIVE(1),
  DEACTIVATED(2);

  private final int code;

  IdentityStatus(int code) {
    this.code = code;
  }

  public int code() {
    return code;
  }

  public static IdentityStatus fromCode(int code) {
    return switch (code) {
      case 1 -> ACTIVE;
      case 2 -> DEACTIVATED;
      default -> throw new IllegalArgumentException("Unsupported OpenIdentity status: " + code);
    };
  }
}
