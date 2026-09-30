package org.openidentity.delegation;
import java.util.List;
public record DelegationEvidence(byte[] registryDomain,List<GrantEvidence> path,byte[] exactEvidenceBytes){
 public DelegationEvidence{registryDomain=registryDomain.clone();path=List.copyOf(path);exactEvidenceBytes=exactEvidenceBytes.clone();}
 @Override public byte[] registryDomain(){return registryDomain.clone();}@Override public byte[] exactEvidenceBytes(){return exactEvidenceBytes.clone();}
}
