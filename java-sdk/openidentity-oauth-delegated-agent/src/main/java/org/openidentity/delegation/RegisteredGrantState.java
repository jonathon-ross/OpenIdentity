package org.openidentity.delegation;
public record RegisteredGrantState(byte[] registryDomain,byte[] grantId,long revision,int status,byte[] rootGrantorStateHash,long delegationGeneration,long registeredAt){
 public static final int ACTIVE=1,REVOKED=2;
 public RegisteredGrantState{registryDomain=registryDomain.clone();grantId=grantId.clone();rootGrantorStateHash=rootGrantorStateHash.clone();}
}
