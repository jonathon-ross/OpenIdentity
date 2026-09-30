package org.openidentity.oauth;
import java.util.List;
public record VerifiedDelegatedSubject(byte[] rootGrantor,byte[] terminalDelegate,byte[] actorAssertionId,byte[] delegationEvidenceId,long earliestExpiresAt,List<Object> effectiveCapabilities){
 public VerifiedDelegatedSubject{rootGrantor=rootGrantor.clone();terminalDelegate=terminalDelegate.clone();actorAssertionId=actorAssertionId.clone();delegationEvidenceId=delegationEvidenceId.clone();effectiveCapabilities=List.copyOf(effectiveCapabilities);}
}
