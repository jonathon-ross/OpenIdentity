package org.openidentity.auth;
public record CurrentAuthenticationState(byte[] identity,byte[] stateHash,boolean active,AuthenticationPolicySnapshot policy){
 public CurrentAuthenticationState{identity=identity.clone();stateHash=stateHash.clone();}
 @Override public byte[] identity(){return identity.clone();}@Override public byte[] stateHash(){return stateHash.clone();}
}
