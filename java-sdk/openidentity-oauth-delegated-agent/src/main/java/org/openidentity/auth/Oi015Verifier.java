package org.openidentity.auth;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.openidentity.crypto.Sha256Multihash;
import org.openidentity.oauth.*;
import java.security.MessageDigest;
import java.util.*;

public final class Oi015Verifier {
 private final AuthenticationStateResolver stateResolver;
 private final long maximumLifetimeSeconds;
 public Oi015Verifier(AuthenticationStateResolver stateResolver,long maximumLifetimeSeconds){
  this.stateResolver=Objects.requireNonNull(stateResolver);this.maximumLifetimeSeconds=maximumLifetimeSeconds;
 }
 public VerifiedAuthenticationAssertion verify(SecuredAuthenticationAssertion secured,byte[] expectedAudience,String expectedPurpose,byte[] expectedNonce,byte[] expectedContextHash,long now){
  AuthenticationAssertion a=secured.assertion();CurrentAuthenticationState state=stateResolver.resolve(a.identity());
  if(state==null)throw new ProfileException(ProfileError.DELEGATION_STATE_UNAVAILABLE);
  if(a.version()!=1)throw new ProfileException(ProfileError.INVALID_REQUEST);
  if(!state.active())throw new ProfileException(ProfileError.INVALID_REQUEST);
  if(!MessageDigest.isEqual(state.identity(),a.identity())||!MessageDigest.isEqual(state.stateHash(),a.stateHash()))throw new ProfileException(ProfileError.INVALID_REQUEST);
  AuthenticationPolicySnapshot p=state.policy();if(p==null)throw new ProfileException(ProfileError.INVALID_REQUEST);
  if(p.generation()!=a.authenticationGeneration())throw new ProfileException(ProfileError.INVALID_REQUEST);
  if(!MessageDigest.isEqual(expectedAudience,a.audience()))throw new ProfileException(ProfileError.INVALID_REQUEST);
  if(!Objects.equals(expectedPurpose,a.purpose()))throw new ProfileException(ProfileError.INVALID_REQUEST);
  if(!MessageDigest.isEqual(expectedNonce,a.nonce()))throw new ProfileException(ProfileError.INVALID_REQUEST);
  if(!MessageDigest.isEqual(expectedContextHash,a.contextHash()))throw new ProfileException(ProfileError.ASSERTION_CONTEXT_BINDING_MISMATCH);
  if(a.expiresAt()<=a.issuedAt()||a.expiresAt()-a.issuedAt()>maximumLifetimeSeconds||now<a.issuedAt()||now>=a.expiresAt())throw new ProfileException(ProfileError.INVALID_REQUEST);
  Map<String,AuthenticationMethod> methods=new HashMap<>();for(AuthenticationMethod m:p.methods())methods.put(HexFormat.of().formatHex(m.methodId()),m);
  Set<String> seen=new HashSet<>();int valid=0;byte[] previous=null;
  for(AuthenticationProof proof:secured.proofs()){
   if(previous!=null&&Arrays.compareUnsigned(previous,proof.methodId())>=0)throw new ProfileException(ProfileError.INVALID_REQUEST);
   previous=proof.methodId();String id=HexFormat.of().formatHex(proof.methodId());if(!seen.add(id))throw new ProfileException(ProfileError.INVALID_REQUEST);
   AuthenticationMethod method=methods.get(id);if(method==null)throw new ProfileException(ProfileError.INVALID_REQUEST);
   byte[] signing=AuthenticationAssertionCodec.signingBytes(a,proof.methodId());
   Ed25519Signer verifier=new Ed25519Signer();verifier.init(false,new Ed25519PublicKeyParameters(method.ed25519PublicKey(),0));verifier.update(signing,0,signing.length);
   if(!verifier.verifySignature(proof.signature()))throw new ProfileException(ProfileError.INVALID_REQUEST);valid++;
  }
  if(valid<p.threshold())throw new ProfileException(ProfileError.INVALID_REQUEST);
  return new VerifiedAuthenticationAssertion(a.identity(),Sha256Multihash.digest(a.exactAssertionBytes()),a.contextHash(),a.purpose());
 }
}
