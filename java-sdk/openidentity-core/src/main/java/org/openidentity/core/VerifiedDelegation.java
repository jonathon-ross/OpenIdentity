package org.openidentity.core;
import java.util.List;
public record VerifiedDelegation(byte[] rootGrantor,byte[] terminalDelegate,byte[] actorAssertionId,byte[] delegationEvidenceId,long earliestExpiresAt,List<Object> effectiveCapabilities){
 public VerifiedDelegation{rootGrantor=rootGrantor.clone();terminalDelegate=terminalDelegate.clone();actorAssertionId=actorAssertionId.clone();delegationEvidenceId=delegationEvidenceId.clone();effectiveCapabilities=List.copyOf(effectiveCapabilities);}
 @Override public byte[] rootGrantor(){return rootGrantor.clone();}@Override public byte[] terminalDelegate(){return terminalDelegate.clone();}@Override public byte[] actorAssertionId(){return actorAssertionId.clone();}@Override public byte[] delegationEvidenceId(){return delegationEvidenceId.clone();}
}
