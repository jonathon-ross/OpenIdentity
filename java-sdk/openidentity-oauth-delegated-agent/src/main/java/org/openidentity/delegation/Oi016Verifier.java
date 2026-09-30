package org.openidentity.delegation;

import org.openidentity.crypto.Sha256Multihash;
import org.openidentity.oauth.*;
import java.security.MessageDigest;
import java.util.*;

public final class Oi016Verifier {
 private final Oi014GrantVerifier grantVerifier;
 public Oi016Verifier(Oi014GrantVerifier grantVerifier){this.grantVerifier=Objects.requireNonNull(grantVerifier);}
 public VerifiedDelegatedSubject verify(byte[] exactTokenBytes,long verificationTime){
  DelegatedSubjectToken token;try{token=Oi016Codec.decode(exactTokenBytes);}catch(IllegalArgumentException e){throw new ProfileException(ProfileError.INVALID_REQUEST,e);}
  DelegationEvidence evidence=token.evidence();if(evidence.exactEvidenceBytes().length>1_048_576)throw new ProfileException(ProfileError.INVALID_REQUEST);
  List<VerifiedGrant> grants=new ArrayList<>();Set<String> ids=new HashSet<>();
  for(GrantEvidence ge:evidence.path()){
   if(!ids.add(HexFormat.of().formatHex(ge.grantId())))throw new ProfileException(ProfileError.INVALID_REQUEST);
   VerifiedGrant g=grantVerifier.verify(evidence.registryDomain(),ge.grantBytes(),verificationTime);
   if(!MessageDigest.isEqual(g.grantId(),ge.grantId()))throw new ProfileException(ProfileError.INVALID_REQUEST);grants.add(g);
  }
  VerifiedGrant root=grants.getFirst();if(root.parentGrantId()!=null)throw new ProfileException(ProfileError.INVALID_REQUEST);
  byte[] rootId=root.rootGrantor();long expiry=root.expiresAt();
  for(int i=0;i<grants.size();i++){
   VerifiedGrant g=grants.get(i);if(!MessageDigest.isEqual(rootId,g.rootGrantor()))throw new ProfileException(ProfileError.INVALID_REQUEST);
   if(grants.size()>g.maximumDelegationDepth())throw new ProfileException(ProfileError.INVALID_REQUEST);
   expiry=Math.min(expiry,g.expiresAt());
   if(i>0){VerifiedGrant prev=grants.get(i-1);if(g.parentGrantId()==null||!MessageDigest.isEqual(prev.grantId(),g.parentGrantId()))throw new ProfileException(ProfileError.INVALID_REQUEST);
    if(!MessageDigest.isEqual(prev.delegate(),g.issuer()))throw new ProfileException(ProfileError.INVALID_REQUEST);}
  }
  if(verificationTime>=expiry)throw new ProfileException(ProfileError.DELEGATION_NOT_CURRENTLY_USABLE);
  VerifiedGrant terminal=grants.getLast();byte[] eid=Sha256Multihash.digest(evidence.exactEvidenceBytes());
  return new VerifiedDelegatedSubject(rootId,terminal.delegate(),token.actorAssertionId(),eid,expiry,terminal.effectiveCapabilities());
 }
}
