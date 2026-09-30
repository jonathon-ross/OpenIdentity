package org.openidentity.spring;
import jakarta.servlet.http.HttpServletRequest;
@FunctionalInterface public interface ActorNonceResolver {
 /** Returns the authorization-server expected OI-015 nonce for this exchange. */
 byte[] resolve(HttpServletRequest request);
}
