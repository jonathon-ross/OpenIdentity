package org.openidentity.oauth;
import java.util.List;
public record DelegatedAgentExchangeRequest(
 String authorizationServer,String clientId,String requestedTokenType,
 List<String> resources,List<String> audiences,List<String> scopes,
 byte[] subjectTokenBytes,byte[] actorTokenBytes,byte[] actorNonce,ValidatedDpopProof dpop,long now){
 public DelegatedAgentExchangeRequest{
  resources=List.copyOf(resources);audiences=List.copyOf(audiences);scopes=List.copyOf(scopes);
  subjectTokenBytes=subjectTokenBytes.clone();actorTokenBytes=actorTokenBytes.clone();actorNonce=actorNonce.clone();
 }
 @Override public byte[] subjectTokenBytes(){return subjectTokenBytes.clone();}
 @Override public byte[] actorTokenBytes(){return actorTokenBytes.clone();}\n @Override public byte[] actorNonce(){return actorNonce.clone();}
}
