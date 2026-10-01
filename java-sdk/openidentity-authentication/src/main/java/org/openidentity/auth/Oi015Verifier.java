package org.openidentity.auth;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.openidentity.crypto.Sha256Multihash;
import org.openidentity.core.*;
import java.security.MessageDigest;
import java.util.*;

public final class Oi015Verifier {
 private final AuthenticationStateResolver stateResolver;
 private final long maximumLifetimeSeconds;
 public Oi015Verifier(AuthenticationStateResolver stateResolver,long maximumLifetimeSeconds){
  this.stateResolver=Objects.requireNonNull(stateResolver);this.maximumLifetimeSeconds=maximumLifetimeSeconds;
 }
 public Oi015VerificationResult tryVerify(SecuredAuthenticationAssertion secured,byte[] expectedAudience,String expectedPurpose,byte[] expectedNonce,byte[] expectedContextHash,long now){
  try{
   VerifiedAuthentication v=verify(secured,expectedAudience,expectedPurpose,expectedNonce,expectedContextHash,now);
   return new Oi015VerificationResult(true,false,v.identity(),null);
  }catch(VerificationException e){
   return new Oi015VerificationResult(false,e.error()==VerificationError.ASSERTION_CONTEXT_BINDING_MISMATCH,null,e.error());
  }
 }
 public VerifiedAuthentication verify(SecuredAuthenticationAssertion secured,byte[] expectedAudience,String expectedPurpose,byte[] expectedNonce,byte[] expectedContextHash,long now){
  AuthenticationAssertion a=secured.assertion();CurrentAuthenticationState state=stateResolver.resolve(a.identity());
  if(state==null)throw new VerificationException(VerificationError.STATE_UNAVAILABLE);
  if(a.version()!=1)throw new VerificationException(VerificationError.INVALID_INPUT);
  if(!state.active())throw new VerificationException(VerificationError.INVALID_INPUT);
  if(!MessageDigest.isEqual(state.identity(),a.identity())||!MessageDigest.isEqual(state.stateHash(),a.stateHash()))throw new VerificationException(VerificationError.INVALID_INPUT);
  AuthenticationPolicySnapshot p=state.policy();if(p==null)throw new VerificationException(VerificationError.INVALID_INPUT);
  if(p.generation()!=a.authenticationGeneration())throw new VerificationException(VerificationError.INVALID_INPUT);
  if(!MessageDigest.isEqual(expectedAudience,a.audience()))throw new VerificationException(VerificationError.INVALID_INPUT);
  if(!Objects.equals(expectedPurpose,a.purpose()))throw new VerificationException(VerificationError.INVALID_INPUT);
  if(!MessageDigest.isEqual(expectedNonce,a.nonce()))throw new VerificationException(VerificationError.INVALID_INPUT);
  if(!MessageDigest.isEqual(expectedContextHash,a.contextHash()))throw new VerificationException(VerificationError.ASSERTION_CONTEXT_BINDING_MISMATCH);
  if(a.expiresAt()<=a.issuedAt()||a.expiresAt()-a.issuedAt()>maximumLifetimeSeconds||now<a.issuedAt()||now>=a.expiresAt())throw new VerificationException(VerificationError.INVALID_INPUT);
  Map<String,AuthenticationMethod> methods=new HashMap<>();for(AuthenticationMethod m:p.methods())methods.put(HexFormat.of().formatHex(m.methodId()),m);
  Set<String> seen=new HashSet<>();int valid=0;byte[] previous=null;
  for(AuthenticationProof proof:secured.proofs()){
   if(previous!=null&&Arrays.compareUnsigned(previous,proof.methodId())>=0)throw new VerificationException(VerificationError.INVALID_INPUT);
   previous=proof.methodId();String id=HexFormat.of().formatHex(proof.methodId());if(!seen.add(id))throw new VerificationException(VerificationError.INVALID_INPUT);
   AuthenticationMethod method=methods.get(id);if(method==null)throw new VerificationException(VerificationError.INVALID_INPUT);
   byte[] signing=AuthenticationAssertionCodec.signingBytes(a,proof.methodId());
   Ed25519Signer verifier=new Ed25519Signer();verifier.init(false,new Ed25519PublicKeyParameters(method.ed25519PublicKey(),0));verifier.update(signing,0,signing.length);
   if(!verifier.verifySignature(proof.signature()))throw new VerificationException(VerificationError.INVALID_INPUT);valid++;
  }
  if(valid<p.threshold())throw new VerificationException(VerificationError.INVALID_INPUT);
  return new VerifiedAuthentication(a.identity(),Sha256Multihash.digest(a.exactAssertionBytes()),a.contextHash(),a.purpose());
 }
}
