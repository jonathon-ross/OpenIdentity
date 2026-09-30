package org.openidentity.spring;

import org.openidentity.oauth.AuthorizationDecision;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import java.time.Instant;
import java.util.*;

public final class OpenIdentityJwtClaims {
 private OpenIdentityJwtClaims(){}
 public static void apply(JwtClaimsSet.Builder claims,AuthorizationDecision d){
  claims.subject(HexFormat.of().formatHex(d.subjectIdentity()));
  claims.audience(d.audiences());
  claims.issuedAt(Instant.ofEpochSecond(d.issuedAt()));
  claims.expiresAt(Instant.ofEpochSecond(d.expiresAt()));
  claims.claim("scope",String.join(" ",d.scopes()));
  claims.claim("act",Map.of("sub",HexFormat.of().formatHex(d.actorIdentity())));
  claims.claim("cnf",Map.of("jkt",d.dpopJkt()));
 }
}
