package org.openidentity.core;
public record CanonicalIdentityState(byte[] identity,byte[] stateHash,boolean active,CanonicalAuthenticationAuthority authenticationAuthority){
 public CanonicalIdentityState{identity=identity.clone();stateHash=stateHash.clone();if(identity.length!=32||stateHash.length!=34)throw new IllegalArgumentException("identity state");}
 @Override public byte[] identity(){return identity.clone();}@Override public byte[] stateHash(){return stateHash.clone();}
}