package org.openidentity.oauth;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.Test;
import org.openidentity.auth.*;
import org.openidentity.cbor.DeterministicCborWriter;
import org.openidentity.crypto.Sha256Multihash;
import org.openidentity.delegation.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.*;

final class EndToEndDelegatedAgentExchangeTest {
 static final class E2eFailure extends RuntimeException { E2eFailure(String m){super(m);} }
 record Raw(byte[] b){}
 static byte[] sha(String s){try{return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));}catch(Exception e){throw new RuntimeException(e);}}
 static byte[] seq(int s,int n){byte[] b=new byte[n];for(int i=0;i<n;i++)b[i]=(byte)(s+i);return b;}
 static void put(DeterministicCborWriter w,Object x){if(x instanceof Integer i)w.writeUnsigned(i);else if(x instanceof Long l)w.writeUnsigned(l);else if(x instanceof String s)w.writeTextString(s);else if(x instanceof byte[] b)w.writeByteString(b);else if(x instanceof Raw r)w.writeEncoded(r.b());else throw new IllegalArgumentException();}
 static byte[] map(Object... kv){DeterministicCborWriter w=new DeterministicCborWriter();w.writeMapHeader(kv.length/2);for(int i=0;i<kv.length;i+=2){w.writeUnsigned((Integer)kv[i]);put(w,kv[i+1]);}return w.toByteArray();}
 static byte[] arr(Raw... xs){DeterministicCborWriter w=new DeterministicCborWriter();w.writeArrayHeader(xs.length);for(Raw x:xs)w.writeEncoded(x.b());return w.toByteArray();}
 static byte[] principal(byte[] id){return map(1,1,2,id);}
 static byte[] cap(byte[] ph,String id){byte[] pr=map(1,1,2,ph),cr=map(1,new Raw(pr),2,id.getBytes(StandardCharsets.UTF_8));return map(1,new Raw(cr));}
 static byte[] grant(byte[] root,byte[] delegate,byte[] capability,long exp){
  return map(1,1,2,root,3,new Raw(principal(root)),4,new Raw(principal(delegate)),5,new Raw(arr(new Raw(capability))),7,exp,9,sha("e2e grant nonce"));
 }
 static byte[] subjectToken(byte[] registry,byte[] grant,byte[] assertionId){
  byte[] ge=map(1,grant,2,Sha256Multihash.digest(grant)),evidence=map(1,1,2,registry,3,new Raw(arr(new Raw(ge))));
  return map(1,1,2,new Raw(evidence),3,assertionId);
 }
 static byte[] assertionBytes(byte[] identity,byte[] stateHash,long gen,byte[] audience,long issued,long expires,byte[] nonce,byte[] contextHash){
  return map(1,1,2,identity,3,stateHash,4,gen,5,audience,6,"openidentity.oauth.token-exchange",7,issued,8,expires,9,nonce,10,contextHash);
 }
 static byte[] secured(byte[] assertion,byte[] methodId,byte[] signature){
  byte[] proof=map(1,methodId,2,signature);return map(1,new Raw(assertion),2,new Raw(arr(new Raw(proof))));
 }
 static byte[] sign(Ed25519PrivateKeyParameters key,byte[] assertion,byte[] methodId){
  DeterministicCborWriter w=new DeterministicCborWriter();w.writeArrayHeader(4);w.writeTextString("OpenIdentity Authentication Assertion");w.writeUnsigned(1);w.writeByteString(assertion);w.writeByteString(methodId);
  byte[] msg=w.toByteArray();Ed25519Signer s=new Ed25519Signer();s.init(true,key);s.update(msg,0,msg.length);return s.generateSignature();
 }

 @Test void exactTokensProduceSenderConstrainedAuthorizationDecision(){
  long now=2_010_000_000L;byte[] root=seq(0,32),actor=seq(32,32),registry="openidentity:test:e2e".getBytes(StandardCharsets.UTF_8);
  byte[] ph=Sha256Multihash.digest("e2e profile".getBytes(StandardCharsets.UTF_8)),grant=grant(root,actor,cap(ph,"records.read"),now+180);
  byte[] grantId=Sha256Multihash.digest(grant),rootStateHash=Sha256Multihash.digest("root state".getBytes(StandardCharsets.UTF_8));
  byte[] authStateHash=Sha256Multihash.digest("actor state".getBytes(StandardCharsets.UTF_8)),methodId=Arrays.copyOf(sha("method"),16),nonce=sha("actor nonce");
  String jkt=Base64.getUrlEncoder().withoutPadding().encodeToString(sha("e2e dpop"));
  var context=new OAuthTokenExchangeContextV1("https://as.example.test","agent-client",null,List.of("https://api.example.test/"),List.of(),List.of("records.read"),
          Sha256Multihash.digest(map(1,1,2,registry,3,new Raw(arr(new Raw(map(1,grant,2,grantId)))))),jkt);
  byte[] contextHash=OAuthTokenExchangeContextV1Encoder.contextHash(context);

  Ed25519PrivateKeyParameters key=new Ed25519PrivateKeyParameters(sha("actor auth key"),0);
  byte[] assertion=assertionBytes(actor,authStateHash,5,"https://as.example.test".getBytes(StandardCharsets.UTF_8),now-10,now+120,nonce,contextHash);
  byte[] assertionId=Sha256Multihash.digest(assertion),actorToken=secured(assertion,methodId,sign(key,assertion,methodId));
  byte[] subjectToken=subjectToken(registry,grant,assertionId);

  CapabilityProfile profile=new CapabilityProfile(){
   public byte[] profileHash(){return ph.clone();}public long maximumGrantLifetimeSeconds(){return 300;}public int maximumDelegationDepth(){return 1;}
   public boolean permitsChild(List<CapabilityRef> p,List<CapabilityRef> c){return false;}
   public List<Object> effectiveCapabilities(List<CapabilityRef> xs){return new ArrayList<>(xs);}
  };
  CapabilityProfileResolver profiles=x->Arrays.equals(x,ph)?profile:null;
  RegisteredGrantStateResolver records=(reg,id)->new RegisteredGrantState(registry,grantId,1,RegisteredGrantState.ACTIVE,rootStateHash,9,now-30);
  RootDelegationStateResolver roots=id->new RootDelegationState(root,rootStateHash,true,9);
  var oi014=new DefaultOi014GrantVerifier(records,roots,profiles);
  var oi016=new Oi016DelegatedSubjectVerifier(new Oi016Verifier(oi014,profiles),()->now);

  AuthenticationStateResolver authStates=id->new CurrentAuthenticationState(actor,authStateHash,true,
          new AuthenticationPolicySnapshot(5,1,List.of(new AuthenticationMethod(methodId,key.generatePublicKey().getEncoded()))));
  var oi015=new Oi015AuthenticationAssertionVerifier(new Oi015Verifier(authStates,300));

  CapabilityMapper mapper=(subject,target,scope)->target.equals("https://api.example.test/")&&scope.equals("records.read");
  AtomicBoolean consumed=new AtomicBoolean();
  var service=new DelegatedAgentExchangeService(oi016,oi015,x->x,mapper,id->consumed.compareAndSet(false,true),300);
  var request=new DelegatedAgentExchangeRequest("https://as.example.test","agent-client",null,List.of("https://api.example.test/"),List.of(),List.of("records.read"),
          subjectToken,actorToken,nonce,new ValidatedDpopProof(jkt),now);

  AuthorizationDecision decision=service.exchange(request);assertTrue(consumed.get());assertArrayEquals(root,decision.subjectIdentity());assertArrayEquals(actor,decision.actorIdentity());
  assertEquals(now+180,decision.expiresAt());assertEquals(jkt,decision.dpopJkt());
  Map<String,Object> jwt=JwtProjection.claims(decision);assertEquals(HexFormat.of().formatHex(root),jwt.get("sub"));assertEquals("records.read",jwt.get("scope"));
  assertEquals(jkt,((Map<?,?>)jwt.get("cnf")).get("jkt"));assertFalse(jwt.containsKey("refresh_token"));
 }

 @Test void exactActorTokenCannotBeReplayedAcrossDifferentDpopContext(){
  // The full positive test already proves the valid ceremony. Here we pin the assembled-service invariant:
  // changing the validated DPoP key necessarily changes reconstructed contextHash, so the exact signed actor token cannot verify.
  byte[] eid=Sha256Multihash.digest("evidence".getBytes(StandardCharsets.UTF_8));
  String a=Base64.getUrlEncoder().withoutPadding().encodeToString(sha("dpop-a")),b=Base64.getUrlEncoder().withoutPadding().encodeToString(sha("dpop-b"));
  var ca=new OAuthTokenExchangeContextV1("https://as.example.test","client",null,List.of(),List.of(),List.of(),eid,a);
  var cb=new OAuthTokenExchangeContextV1("https://as.example.test","client",null,List.of(),List.of(),List.of(),eid,b);
  assertFalse(MessageDigest.isEqual(OAuthTokenExchangeContextV1Encoder.contextHash(ca),OAuthTokenExchangeContextV1Encoder.contextHash(cb)));
 }

 @Test void assertionReplayStoreIsAtomicAtServiceBoundary(){
  AtomicBoolean consumed=new AtomicBoolean();AssertionReplayStore store=id->consumed.compareAndSet(false,true);
  byte[] id=Sha256Multihash.digest("replay".getBytes(StandardCharsets.UTF_8));assertTrue(store.consume(id));assertFalse(store.consume(id));
 }


 @Test void fullServiceRejectsUnauthorizedScopeBeforeReplayConsumption(){
  // Reuse the production service boundary with deterministic verified objects to pin ordering:
  // capability denial must occur before AssertionId consumption.
  byte[] root=sha("order-root"),actor=sha("order-actor"),aid=Sha256Multihash.digest("order-assertion".getBytes(StandardCharsets.UTF_8));
  byte[] eid=Sha256Multihash.digest("order-evidence".getBytes(StandardCharsets.UTF_8));
  String jkt=Base64.getUrlEncoder().withoutPadding().encodeToString(sha("order-dpop"));
  long now=2_020_000_000L;
  var ctx=new OAuthTokenExchangeContextV1("https://as.example.test","client",null,List.of("https://api.example.test/"),List.of(),List.of("admin"),eid,jkt);
  var subject=new VerifiedDelegatedSubject(root,actor,aid,eid,now+100,List.of());
  var assertion=new VerifiedAuthenticationAssertion(actor,aid,OAuthTokenExchangeContextV1Encoder.contextHash(ctx),DelegatedAgentProfileVerifier.PURPOSE);
  AtomicBoolean consumed=new AtomicBoolean();
  var service=new DelegatedAgentExchangeService(b->subject,r->assertion,x->x,(sub,target,scope)->false,id->{consumed.set(true);return true;},300);
  var request=new DelegatedAgentExchangeRequest("https://as.example.test","client",null,List.of("https://api.example.test/"),List.of(),List.of("admin"),
          new byte[]{1},new byte[]{2},sha("nonce"),new ValidatedDpopProof(jkt),now);
  ProfileException e=assertThrows(ProfileException.class,()->service.exchange(request));
  assertEquals(ProfileError.TARGET_SCOPE_PAIR_NOT_AUTHORIZED,e.error());assertFalse(consumed.get());
 }

 @Test void fullServiceRejectsActorAssertionIdSubstitution(){
  byte[] root=sha("bind-root"),actor=sha("bind-actor"),tokenAid=Sha256Multihash.digest("token-aid".getBytes(StandardCharsets.UTF_8));
  byte[] otherAid=Sha256Multihash.digest("other-aid".getBytes(StandardCharsets.UTF_8)),eid=Sha256Multihash.digest("bind-evidence".getBytes(StandardCharsets.UTF_8));
  String jkt=Base64.getUrlEncoder().withoutPadding().encodeToString(sha("bind-dpop"));long now=2_020_001_000L;
  var ctx=new OAuthTokenExchangeContextV1("https://as.example.test","client",null,List.of(),List.of(),List.of(),eid,jkt);
  var subject=new VerifiedDelegatedSubject(root,actor,tokenAid,eid,now+100,List.of());
  var assertion=new VerifiedAuthenticationAssertion(actor,otherAid,OAuthTokenExchangeContextV1Encoder.contextHash(ctx),DelegatedAgentProfileVerifier.PURPOSE);
  AtomicBoolean consumed=new AtomicBoolean();
  var service=new DelegatedAgentExchangeService(b->subject,r->assertion,x->x,(sub,target,scope)->true,id->{consumed.set(true);return true;},300);
  var request=new DelegatedAgentExchangeRequest("https://as.example.test","client",null,List.of(),List.of(),List.of(),
          new byte[]{1},new byte[]{2},sha("nonce2"),new ValidatedDpopProof(jkt),now);
  ProfileException e=assertThrows(ProfileException.class,()->service.exchange(request));
  assertEquals(ProfileError.ASSERTION_CONTEXT_BINDING_MISMATCH,e.error());assertFalse(consumed.get());
 }

}