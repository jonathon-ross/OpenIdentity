package org.openidentity.spring;
import jakarta.servlet.http.HttpServletRequest;
@FunctionalInterface public interface ValidatedDpopJktResolver {
 /** Returns the RFC 7638 jkt only after complete RFC 9449 proof validation, or null if no valid proof is available. */
 String resolve(HttpServletRequest request);
}
