package org.openidentity.oauth;
import java.util.List;
public record DelegatedAgentExchangeRequest(
 String authorizationServer,String clientId,String requestedTokenType,
 List<String> resources,List<String> audiences,List<String> scopes,
 byte[] subjectTokenBytes,byte[] actorTokenBytes,ValidatedDpopProof dpop,long now){
 public DelegatedAgentExchangeRequest{
  resources=List.copyOf(resources);audiences=List.copyOf(audiences);scopes=List.copyOf(scopes);
  subjectTokenBytes=subjectTokenBytes.clone();actorTokenBytes=actorTokenBytes.clone();
 }
 @Override public byte[] subjectTokenBytes(){return subjectTokenBytes.clone();}
 @Override public byte[] actorTokenBytes(){return actorTokenBytes.clone();}
}
