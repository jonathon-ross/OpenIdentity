package org.openidentity.spring;
import jakarta.servlet.http.HttpServletRequest;
@FunctionalInterface public interface ValidatedDpopJktResolver {
 /** Returns a completely RFC 9449-validated Spring Jwt and its RFC 7638 public-key thumbprint, or null if no proof is available. */
 ValidatedDpopProofResult resolve(HttpServletRequest request);
}
