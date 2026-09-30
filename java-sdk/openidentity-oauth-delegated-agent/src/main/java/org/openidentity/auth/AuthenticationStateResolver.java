package org.openidentity.auth;
@FunctionalInterface public interface AuthenticationStateResolver {
 CurrentAuthenticationState resolve(byte[] identity);
}
