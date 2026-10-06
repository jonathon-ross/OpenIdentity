package org.openidentity.credentials;

import java.net.URI;
import java.util.*;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.*;

public final class OpenIdentityCredential {
  public static final int VERSION = 1;
  private final byte[] id, subject;
  private final IdentityId issuer;
  private final StateHash issuanceStateHash;
  private final long validFrom;
  private final Long validUntil;
  private final String profile;
  private final Map<String, Object> claims;

  public OpenIdentityCredential(
      byte[] id,
      IdentityId issuer,
      StateHash issuanceStateHash,
      long validFrom,
      Long validUntil,
      String profile,
      byte[] subject,
      Map<String, Object> claims) {
    Objects.requireNonNull(id);
    Objects.requireNonNull(issuer);
    Objects.requireNonNull(issuanceStateHash);
    Objects.requireNonNull(profile);
    Objects.requireNonNull(subject);
    Objects.requireNonNull(claims);
    if (id.length != 32) throw new IllegalArgumentException("credentialId must be 32 bytes");
    if (validFrom < 0 || (validUntil != null && (validUntil < 0 || validUntil <= validFrom)))
      throw new IllegalArgumentException("Invalid credential validity period");
    URI u = URI.create(profile);
    if (!u.isAbsolute())
      throw new IllegalArgumentException("credentialProfile must be absolute URI");
    if (subject.length == 0)
      throw new IllegalArgumentException("credentialSubject must not be empty");
    if (claims.isEmpty()) throw new IllegalArgumentException("claims must not be empty");
    this.id = id.clone();
    this.issuer = issuer;
    this.issuanceStateHash = issuanceStateHash;
    this.validFrom = validFrom;
    this.validUntil = validUntil;
    this.profile = profile;
    this.subject = subject.clone();
    this.claims = Map.copyOf(claims);
  }

  public byte[] encode() {
    return OpenIdentityCborEncoder.encodeCredential(
        id, issuer, issuanceStateHash, validFrom, validUntil, profile, subject, claims);
  }

  public byte[] id() {
    return id.clone();
  }

  public IdentityId issuer() {
    return issuer;
  }

  public StateHash issuanceStateHash() {
    return issuanceStateHash;
  }

  public long validFrom() {
    return validFrom;
  }

  public Long validUntil() {
    return validUntil;
  }

  public String profile() {
    return profile;
  }

  public byte[] subject() {
    return subject.clone();
  }

  public Map<String, Object> claims() {
    return claims;
  }
}
