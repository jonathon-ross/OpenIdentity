package org.openidentity.spring;

import org.openidentity.oauth.AuthorizationDecision;
import org.openidentity.oauth.DelegatedAgentExchangeRequest;
import org.openidentity.oauth.ProfileException;

@FunctionalInterface
public interface OpenIdentityExchange {
 AuthorizationDecision exchange(DelegatedAgentExchangeRequest request) throws ProfileException;
}
