package org.openidentity.spring.auth;
import org.openidentity.spring.OpenIdentityPrincipal;import org.springframework.security.authentication.AbstractAuthenticationToken;import org.springframework.security.core.authority.SimpleGrantedAuthority;import java.util.*;
public final class OpenIdentityNativeAuthenticationToken extends AbstractAuthenticationToken implements OpenIdentityPrincipal {
 private final byte[] identity,assertionId;
 public OpenIdentityNativeAuthenticationToken(byte[] identity,byte[] assertionId){super(List.of(new SimpleGrantedAuthority("ROLE_OPENIDENTITY")));this.identity=identity.clone();this.assertionId=assertionId.clone();setAuthenticated(true);}
 @Override public Object getPrincipal(){return openIdentityIdHex();}@Override public Object getCredentials(){return "";}@Override public byte[] openIdentityId(){return identity.clone();}public byte[] assertionId(){return assertionId.clone();}
}