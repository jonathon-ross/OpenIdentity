package org.openidentity.spring;
import org.springframework.security.core.Authentication;
public interface OpenIdentityPrincipal extends Authentication {
 byte[] openIdentityId();
 default String openIdentityIdHex(){return java.util.HexFormat.of().formatHex(openIdentityId());}
}