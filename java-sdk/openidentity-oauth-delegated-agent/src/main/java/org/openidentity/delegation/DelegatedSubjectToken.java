package org.openidentity.delegation;
public record DelegatedSubjectToken(DelegationEvidence evidence,byte[] actorAssertionId){
 public DelegatedSubjectToken{actorAssertionId=actorAssertionId.clone();}
 @Override public byte[] actorAssertionId(){return actorAssertionId.clone();}
}
