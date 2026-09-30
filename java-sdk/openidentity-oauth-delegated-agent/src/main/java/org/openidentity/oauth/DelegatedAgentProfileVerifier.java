package org.openidentity.oauth;

import java.security.MessageDigest;
import java.util.*;

public final class DelegatedAgentProfileVerifier {
    public static final String PURPOSE="openidentity.oauth.token-exchange";
    private DelegatedAgentProfileVerifier(){}
    public static AuthorizationDecision authorize(
            VerifiedDelegatedSubject subject,VerifiedAuthenticationAssertion actor,
            OAuthTokenExchangeContextV1 context,ValidatedDpopProof dpop,
            List<String> resolvedTargets,List<String> requestedScopes,
            CapabilityMapper mapper,long now,long maximumLifetimeSeconds){
        Objects.requireNonNull(subject);Objects.requireNonNull(actor);Objects.requireNonNull(context);Objects.requireNonNull(dpop);Objects.requireNonNull(mapper);
        if(!PURPOSE.equals(actor.purpose()))throw new IllegalArgumentException("INVALID_OI015_PURPOSE");
        if(!MessageDigest.isEqual(subject.actorAssertionId(),actor.assertionId()))throw new IllegalArgumentException("ASSERTION_CONTEXT_BINDING_MISMATCH");
        if(!MessageDigest.isEqual(subject.terminalDelegate(),actor.identity()))throw new IllegalArgumentException("ACTOR_BINDING_MISMATCH");
        byte[] expectedHash=OAuthTokenExchangeContextV1Encoder.contextHash(context);
        if(!MessageDigest.isEqual(expectedHash,actor.contextHash()))throw new IllegalArgumentException("ASSERTION_CONTEXT_BINDING_MISMATCH");
        if(!MessageDigest.isEqual(subject.delegationEvidenceId(),context.delegationEvidenceId()))throw new IllegalArgumentException("DELEGATION_EVIDENCE_MISMATCH");
        if(!dpop.jkt().equals(context.dpopJkt()))throw new IllegalArgumentException("DPOP_CONTEXT_MISMATCH");
        List<String> targets=List.copyOf(resolvedTargets),scopes=List.copyOf(requestedScopes);
        for(String target:targets)for(String scope:scopes)if(!mapper.explicitlyAllows(subject,target,scope))throw new IllegalArgumentException("TARGET_SCOPE_PAIR_NOT_AUTHORIZED");
        long deploymentExp=Math.addExact(now,maximumLifetimeSeconds);
        long exp=Math.min(subject.earliestExpiresAt(),deploymentExp);
        if(exp<=now)throw new IllegalArgumentException("DELEGATION_NOT_CURRENTLY_USABLE");
        return new AuthorizationDecision(subject.rootGrantor(),subject.terminalDelegate(),targets,scopes,dpop.jkt(),now,exp);
    }
}
