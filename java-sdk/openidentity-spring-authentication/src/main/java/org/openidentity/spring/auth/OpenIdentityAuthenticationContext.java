package org.openidentity.spring.auth;
import org.openidentity.crypto.Sha256Multihash;import java.nio.charset.StandardCharsets;
public final class OpenIdentityAuthenticationContext {
 private OpenIdentityAuthenticationContext(){}
 public static byte[] oauthAuthorizationContext(String requestTarget){
  if(requestTarget==null||requestTarget.isBlank())throw new IllegalArgumentException("requestTarget");
  return Sha256Multihash.digest(("OpenIdentity OAuth Authentication Context\n"+requestTarget).getBytes(StandardCharsets.UTF_8));
 }
}