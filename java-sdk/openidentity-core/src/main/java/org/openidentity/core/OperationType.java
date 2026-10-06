package org.openidentity.core;

/** OpenIdentity Protocol v0.1 operation type registry. */
public enum OperationType {
  CREATE(1),
  ROTATE_CONTROLLER(2),
  RECOVER(3),
  DEACTIVATE(4),
  SET_ASSERTION_POLICY(5);

  private final int code;

  OperationType(int code) {
    this.code = code;
  }

  public int code() {
    return code;
  }

  public static OperationType fromCode(int code) {
    return switch (code) {
      case 1 -> CREATE;
      case 2 -> ROTATE_CONTROLLER;
      case 3 -> RECOVER;
      case 4 -> DEACTIVATE;
      case 5 -> SET_ASSERTION_POLICY;
      default ->
          throw new IllegalArgumentException("Unsupported OpenIdentity operation type: " + code);
    };
  }
}
