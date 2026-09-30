package org.openidentity.oauth;

import java.util.List;
import java.util.Objects;

public record OAuthTokenExchangeContextV1(
        String authorizationServer,String clientId,String requestedTokenType,
        List<String> resources,List<String> audiences,List<String> scopes,
        byte[] delegationEvidenceId,String dpopJkt){
    public OAuthTokenExchangeContextV1{
        Objects.requireNonNull(authorizationServer);Objects.requireNonNull(clientId);Objects.requireNonNull(resources);
        Objects.requireNonNull(audiences);Objects.requireNonNull(scopes);Objects.requireNonNull(delegationEvidenceId);Objects.requireNonNull(dpopJkt);
        resources=List.copyOf(resources);audiences=List.copyOf(audiences);scopes=List.copyOf(scopes);delegationEvidenceId=delegationEvidenceId.clone();
    }
    @Override public byte[] delegationEvidenceId(){return delegationEvidenceId.clone();}
}
