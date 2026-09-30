package org.openidentity.delegation;
public record RootDelegationState(byte[] identity,byte[] stateHash,boolean active,long delegationGeneration){
 public RootDelegationState{identity=identity.clone();stateHash=stateHash.clone();}
}
