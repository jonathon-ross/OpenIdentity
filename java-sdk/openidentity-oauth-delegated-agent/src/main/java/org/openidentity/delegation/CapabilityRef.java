package org.openidentity.delegation;
public record CapabilityRef(byte[] profileHash,byte[] capabilityId,byte[] resourceConstraint){
 public CapabilityRef{profileHash=profileHash.clone();capabilityId=capabilityId.clone();resourceConstraint=resourceConstraint==null?null:resourceConstraint.clone();}
}
