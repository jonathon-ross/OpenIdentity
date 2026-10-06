package org.openidentity.crypto;

public enum SigningDomain {
  OPERATION("OpenIdentity Operation"),
  CONTROLLER_PROOF("OpenIdentity Controller Proof"),
  RECOVERY("OpenIdentity Recovery"),
  CREDENTIAL("OpenIdentity Credential");

  private final String value;

  SigningDomain(String value) {
    this.value = value;
  }

  public String value() {
    return value;
  }
}
