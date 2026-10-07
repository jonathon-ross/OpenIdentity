package org.openidentity.core;

import java.util.*;

public record VerifiedIdentityCreation(byte[] identity,byte[] stateBytes,byte[] stateHash,int protocolVersion,int stateVersion,long sequence,int status){
 public VerifiedIdentityCreation{
  Objects.requireNonNull(identity);Objects.requireNonNull(stateBytes);Objects.requireNonNull(stateHash);
  identity=identity.clone();stateBytes=stateBytes.clone();stateHash=stateHash.clone();
  if(identity.length!=32)throw new IllegalArgumentException("identity must be 32 bytes");
  if(stateHash.length!=34)throw new IllegalArgumentException("StateHash must be 34 bytes");
  if(protocolVersion<1||stateVersion<1||sequence!=1)throw new IllegalArgumentException("invalid creation metadata");
 }
 @Override public byte[] identity(){return identity.clone();}@Override public byte[] stateBytes(){return stateBytes.clone();}@Override public byte[] stateHash(){return stateHash.clone();}
}
