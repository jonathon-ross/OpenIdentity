package org.openidentity.oauth;

import java.util.*;

public final class DelegatedAgentExchangeService {
    private final DelegatedSubjectVerifier subjectVerifier;
    private final AuthenticationAssertionVerifier actorVerifier;
    private final TargetResolver targetResolver;
    private final CapabilityMapper capabilityMapper;
    private final AssertionReplayStore replayStore;
    private final long maximumLifetimeSeconds;

    public DelegatedAgentExchangeService(
            DelegatedSubjectVerifier subjectVerifier,
            AuthenticationAssertionVerifier actorVerifier,
            TargetResolver targetResolver,
            CapabilityMapper capabilityMapper,
            AssertionReplayStore replayStore,
            long maximumLifetimeSeconds) {
        this.subjectVerifier=Objects.requireNonNull(subjectVerifier);
        this.actorVerifier=Objects.requireNonNull(actorVerifier);
        this.targetResolver=Objects.requireNonNull(targetResolver);
        this.capabilityMapper=Objects.requireNonNull(capabilityMapper);
        this.replayStore=Objects.requireNonNull(replayStore);
        if(maximumLifetimeSeconds<=0)throw new IllegalArgumentException("maximumLifetimeSeconds");
        this.maximumLifetimeSeconds=maximumLifetimeSeconds;
    }

    public AuthorizationDecision exchange(DelegatedAgentExchangeRequest request) {
        Objects.requireNonNull(request);
        if(request.dpop()==null)throw new ProfileException(ProfileError.DPOP_REQUIRED);

        VerifiedDelegatedSubject subject=subjectVerifier.verify(request.subjectTokenBytes());

        List<String> targets=resolveTargets(request.resources(),request.audiences());
        OAuthTokenExchangeContextV1 context=new OAuthTokenExchangeContextV1(
                request.authorizationServer(),request.clientId(),request.requestedTokenType(),
                request.resources(),request.audiences(),request.scopes(),
                subject.delegationEvidenceId(),request.dpop().jkt());
        byte[] contextHash=OAuthTokenExchangeContextV1Encoder.contextHash(context);
        VerifiedAuthenticationAssertion actor=actorVerifier.verify(new AuthenticationVerificationRequest(
                request.actorTokenBytes(),request.authorizationServer().getBytes(java.nio.charset.StandardCharsets.UTF_8),
                DelegatedAgentProfileVerifier.PURPOSE,request.actorNonce(),contextHash,request.now()));

        AuthorizationDecision decision;
        try {
            decision=DelegatedAgentProfileVerifier.authorize(
                    subject,actor,context,request.dpop(),targets,request.scopes(),
                    capabilityMapper,request.now(),maximumLifetimeSeconds);
        } catch (ProfileException e) {
            throw e;
        } catch (IllegalArgumentException e) {
            throw translate(e);
        }

        // Consume only after every verification/authorization check succeeds.
        // Implementations must provide an atomic store.
        if(!replayStore.consume(actor.assertionId()))throw new ProfileException(ProfileError.ASSERTION_REPLAY);
        return decision;
    }

    private List<String> resolveTargets(List<String> resources,List<String> audiences) {
        LinkedHashSet<String> resolved=new LinkedHashSet<>();
        for(String x:resources)resolved.add(targetResolver.resolve(x));
        for(String x:audiences)resolved.add(targetResolver.resolve(x));
        return List.copyOf(resolved);
    }

    private static ProfileException translate(IllegalArgumentException e) {
        ProfileError p;
        try { p=ProfileError.valueOf(e.getMessage()); }
        catch (RuntimeException ignored) { p=ProfileError.INVALID_REQUEST; }
        return new ProfileException(p,e);
    }
}
