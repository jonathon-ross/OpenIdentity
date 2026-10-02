package org.openidentity.spring.ad;
import org.springframework.security.authentication.AbstractAuthenticationToken;import org.openidentity.spring.OpenIdentityPrincipal;import org.springframework.security.core.authority.SimpleGrantedAuthority;import java.util.*;
public final class OpenIdentityAdAuthenticationToken extends AbstractAuthenticationToken implements OpenIdentityPrincipal {
 private final OpenIdentityActiveDirectoryAuthentication result;
 public OpenIdentityAdAuthenticationToken(OpenIdentityActiveDirectoryAuthentication result){
  super(authorities(result));this.result=Objects.requireNonNull(result);setAuthenticated(true);
 }
 private static Collection<SimpleGrantedAuthority> authorities(OpenIdentityActiveDirectoryAuthentication r){
  Objects.requireNonNull(r);return r.bound()?List.of(new SimpleGrantedAuthority("ROLE_OPENIDENTITY"),new SimpleGrantedAuthority("ROLE_AD_AUTHENTICATED")):List.of(new SimpleGrantedAuthority("ROLE_AD_AUTHENTICATED"));
 }
 @Override public Object getCredentials(){return "";}
 @Override public Object getPrincipal(){return result.bound()?HexFormat.of().formatHex(result.openIdentityId()):result.kerberosPrincipal();}
 public OpenIdentityActiveDirectoryAuthentication result(){return result;}
 @Override public byte[] openIdentityId(){if(!result.bound())throw new IllegalStateException("OpenIdentity identity is not bound");return result.openIdentityId();}
}