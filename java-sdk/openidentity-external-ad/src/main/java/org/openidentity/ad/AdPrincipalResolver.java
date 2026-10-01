package org.openidentity.ad;
public interface AdPrincipalResolver {
 VerifiedAdPrincipal resolve(AdAuthenticationEvidence evidence);
}