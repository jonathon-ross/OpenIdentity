package org.openidentity.oauth;
import java.util.*;
public final class JwtProjection {
 private JwtProjection(){}
 public static Map<String,Object> claims(AuthorizationDecision d){
  Map<String,Object> act=Map.of("sub",HexFormat.of().formatHex(d.actorIdentity()));
  Map<String,Object> cnf=Map.of("jkt",d.dpopJkt());
  Map<String,Object> out=new LinkedHashMap<>();out.put("sub",HexFormat.of().formatHex(d.subjectIdentity()));out.put("act",act);
  out.put("aud",d.audiences());out.put("scope",String.join(" ",d.scopes()));out.put("cnf",cnf);out.put("iat",d.issuedAt());out.put("exp",d.expiresAt());return Collections.unmodifiableMap(out);
 }
}
