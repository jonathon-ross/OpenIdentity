package org.openidentity.samples;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.openidentity.auth.*;
import org.openidentity.cbor.DeterministicCborWriter;
import org.openidentity.crypto.Sha256Multihash;
import org.openidentity.delegation.*;
import org.openidentity.oauth.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

public final class SampleOpenIdentityFixture {
 public record Material(byte[] subjectToken,byte[] actorToken,byte[] nonce,String dpopJkt,
   DelegatedAgentExchangeService exchangeService){}

 record Raw(byte[] bytes){}
 private static byte[] sha(String s){try{return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));}catch(Exception e){throw new IllegalStateException(e);}}
 private static byte[] seq(int s,int n){byte[] b=new byte[n];for(int i=0;i<n;i++)b[i]=(byte)(s+i);return b;}
 private static void put(DeterministicCborWriter w,Object x){if(x instanceof Integer i)w.writeUnsigned(i);else if(x instanceof Long l)w.writeUnsigned(l);else if(x instanceof String z)w.writeTextString(z);else if(x instanceof byte[] b)w.writeByteString(b);else if(x instanceof Raw r)w.writeEncoded(r.bytes());else throw new IllegalArgumentException();}
 private static byte[] map(Object... kv){var w=new DeterministicCborWriter();w.writeMapHeader(kv.length/2);for(int i=0;i<kv.length;i+=2){w.writeUnsigned((Integer)kv[i]);put(w,kv[i+1]);}return w.toByteArray();}
 private static byte[] arr(Raw... xs){var w=new DeterministicCborWriter();w.writeArrayHeader(xs.length);for(Raw x:xs)w.writeEncoded(x.bytes());return w.toByteArray();}
 private static byte[] principal(byte[] id){return map(1,1,2,id);}
 private static byte[] capability(byte[] ph){byte[] pr=map(1,1,2,ph),cr=map(1,new Raw(pr),2,"records.read".getBytes(StandardCharsets.UTF_8));return map(1,new Raw(cr));}
 private static byte[] sign(Ed25519PrivateKeyParameters key,byte[] assertion,byte[] methodId){
  var w=new DeterministicCborWriter();w.writeArrayHeader(4);w.writeTextString("OpenIdentity Authentication Assertion");w.writeUnsigned(1);w.writeByteString(assertion);w.writeByteString(methodId);
  byte[] m=w.toByteArray();var s=new Ed25519Signer();s.init(true,key);s.update(m,0,m.length);return s.generateSignature();
 }

 public static Material create(){
  long now=Instant.now().getEpochSecond();byte[] root=seq(0,32),actor=seq(32,32),registry="openidentity:sample:registry".getBytes(StandardCharsets.UTF_8);
  byte[] ph=Sha256Multihash.digest("sample capability profile".getBytes(StandardCharsets.UTF_8)),nonce=sha("sample actor nonce");
  String jkt=Base64.getUrlEncoder().withoutPadding().encodeToString(sha("sample dpop key"));
  byte[] cap=capability(ph),grant=map(1,1,2,root,3,new Raw(principal(root)),4,new Raw(principal(actor)),5,new Raw(arr(new Raw(cap))),7,now+240,9,sha("sample grant nonce"));
  byte[] gid=Sha256Multihash.digest(grant),ge=map(1,grant,2,gid),evidence=map(1,1,2,registry,3,new Raw(arr(new Raw(ge)))),eid=Sha256Multihash.digest(evidence);
  var context=new OAuthTokenExchangeContextV1("http://127.0.0.1:9000","agent-client",null,List.of("https://api.example.test/"),List.of(),List.of("records.read"),eid,jkt);
  byte[] authState=Sha256Multihash.digest("sample actor state".getBytes(StandardCharsets.UTF_8)),ctx=OAuthTokenExchangeContextV1Encoder.contextHash(context),methodId=Arrays.copyOf(sha("sample method"),16);
  Ed25519PrivateKeyParameters key=new Ed25519PrivateKeyParameters(sha("sample auth key"),0);
  byte[] assertion=map(1,1,2,actor,3,authState,4,5L,5,"http://127.0.0.1:9000".getBytes(StandardCharsets.UTF_8),6,DelegatedAgentProfileVerifier.PURPOSE,7,now-5,8,now+120,9,nonce,10,ctx);
  byte[] aid=Sha256Multihash.digest(assertion),proof=map(1,methodId,2,sign(key,assertion,methodId)),actorToken=map(1,new Raw(assertion),2,new Raw(arr(new Raw(proof))));
  byte[] subjectToken=map(1,1,2,new Raw(evidence),3,aid);

  byte[] rootState=Sha256Multihash.digest("sample root state".getBytes(StandardCharsets.UTF_8));
  CapabilityProfile profile=new CapabilityProfile(){
   public byte[] profileHash(){return ph.clone();}public long maximumGrantLifetimeSeconds(){return 300;}public int maximumDelegationDepth(){return 1;}
   public boolean permitsChild(List<CapabilityRef> p,List<CapabilityRef> c){return false;}public List<Object> effectiveCapabilities(List<CapabilityRef> xs){return new ArrayList<>(xs);}
  };
  CapabilityProfileResolver profiles=x->Arrays.equals(x,ph)?profile:null;
  RegisteredGrantStateResolver records=(reg,id)->Arrays.equals(id,gid)?new RegisteredGrantState(registry,gid,1,RegisteredGrantState.ACTIVE,rootState,9,now-10):null;
  RootDelegationStateResolver roots=id->new RootDelegationState(root,rootState,true,9);
  var oi014=new DefaultOi014GrantVerifier(records,roots,profiles);
  var oi016=new Oi016DelegatedSubjectVerifier(new Oi016Verifier(oi014,profiles),() -> Instant.now().getEpochSecond());
  AuthenticationStateResolver states=id->new CurrentAuthenticationState(actor,authState,true,new AuthenticationPolicySnapshot(5,1,List.of(new AuthenticationMethod(methodId,key.generatePublicKey().getEncoded()))));
  var oi015=new Oi015AuthenticationAssertionVerifier(new Oi015Verifier(states,300));
  CapabilityMapper mapper=(subject,target,scope)->target.equals("https://api.example.test/")&&scope.equals("records.read");
  Set<String> consumed=Collections.synchronizedSet(new HashSet<>());
  AssertionReplayStore replay=id->consumed.add(HexFormat.of().formatHex(id));
  return new Material(subjectToken,actorToken,nonce,jkt,new DelegatedAgentExchangeService(oi016,oi015,x->x,mapper,replay,300));
 }
 private SampleOpenIdentityFixture(){}
}
