package org.openidentity.oauth;
import java.util.List;
public record AuthorizationDecision(byte[] subjectIdentity,byte[] actorIdentity,List<String> audiences,List<String> scopes,String dpopJkt,long issuedAt,long expiresAt){
 public AuthorizationDecision{subjectIdentity=subjectIdentity.clone();actorIdentity=actorIdentity.clone();audiences=List.copyOf(audiences);scopes=List.copyOf(scopes);}
}
