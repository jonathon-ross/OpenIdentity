package org.openidentity.delegation;

import org.openidentity.crypto.Sha256Multihash;
import org.openidentity.core.*;
import java.security.MessageDigest;
import java.util.*;

public final class DefaultOi014GrantVerifier implements Oi014GrantVerifier {
 private final RegisteredGrantStateResolver records;
 private final RootDelegationStateResolver roots;
 private final CapabilityProfileResolver profiles;

 public DefaultOi014GrantVerifier(RegisteredGrantStateResolver records,RootDelegationStateResolver roots,CapabilityProfileResolver profiles){
  this.records=Objects.requireNonNull(records);this.roots=Objects.requireNonNull(roots);this.profiles=Objects.requireNonNull(profiles);
 }

 @Override public VerifiedGrant verify(byte[] registryDomain,byte[] exactGrantBytes,long now){
  DelegationGrant g;try{g=Oi014Codec.decodeGrant(exactGrantBytes);}catch(IllegalArgumentException e){throw new VerificationException(VerificationError.INVALID_INPUT,e);}
  RegisteredGrantState record=records.resolve(registryDomain,g.grantId());if(record==null)throw new VerificationException(VerificationError.STATE_UNAVAILABLE);
  if(record.status()!=RegisteredGrantState.ACTIVE)throw new VerificationException(VerificationError.NOT_CURRENTLY_USABLE);
  if(!MessageDigest.isEqual(record.registryDomain(),registryDomain)||!MessageDigest.isEqual(record.grantId(),g.grantId()))throw new VerificationException(VerificationError.INVALID_INPUT);
  RootDelegationState root=roots.resolve(g.rootGrantor());if(root==null)throw new VerificationException(VerificationError.STATE_UNAVAILABLE);
  if(!root.active()||!MessageDigest.isEqual(root.identity(),g.rootGrantor())||!MessageDigest.isEqual(root.stateHash(),record.rootGrantorStateHash())||root.delegationGeneration()!=record.delegationGeneration())
   throw new VerificationException(VerificationError.NOT_CURRENTLY_USABLE);
  if(g.notBefore()!=null&&now<g.notBefore()||now>=g.expiresAt())throw new VerificationException(VerificationError.NOT_CURRENTLY_USABLE);
  if(g.expiresAt()<=record.registeredAt())throw new VerificationException(VerificationError.INVALID_INPUT);
  if(g.issuer() instanceof ProfilePrincipal||g.delegate() instanceof ProfilePrincipal)throw new VerificationException(VerificationError.CAPABILITY_PROFILE_UNAVAILABLE);
  OpenIdentityPrincipal issuer=(OpenIdentityPrincipal)g.issuer(),delegate=(OpenIdentityPrincipal)g.delegate();
  if(g.parentGrantId()==null&&!MessageDigest.isEqual(issuer.identity(),g.rootGrantor()))throw new VerificationException(VerificationError.INVALID_INPUT);

  Map<String,List<CapabilityRef>> byProfile=new LinkedHashMap<>();for(CapabilityRef c:g.capabilities())byProfile.computeIfAbsent(HexFormat.of().formatHex(c.profileHash()),k->new ArrayList<>()).add(c);
  List<Object> effective=new ArrayList<>();int maxDepth=Integer.MAX_VALUE;
  for(List<CapabilityRef> cs:byProfile.values()){
   byte[] ph=cs.getFirst().profileHash();CapabilityProfile p=profiles.resolve(ph);if(p==null||!MessageDigest.isEqual(p.profileHash(),ph))throw new VerificationException(VerificationError.CAPABILITY_PROFILE_UNAVAILABLE);
   if(p.maximumGrantLifetimeSeconds()<=0||p.maximumDelegationDepth()<1)throw new VerificationException(VerificationError.INVALID_INPUT);
   long lifetime=g.expiresAt()-record.registeredAt();if(lifetime>p.maximumGrantLifetimeSeconds())throw new VerificationException(VerificationError.NOT_CURRENTLY_USABLE);
   maxDepth=Math.min(maxDepth,p.maximumDelegationDepth());effective.addAll(p.effectiveCapabilities(cs));
  }
  return new VerifiedGrant(g.grantId(),g.rootGrantor(),issuer.identity(),delegate.identity(),g.parentGrantId(),g.expiresAt(),g.capabilities(),effective,maxDepth);
 }
}
