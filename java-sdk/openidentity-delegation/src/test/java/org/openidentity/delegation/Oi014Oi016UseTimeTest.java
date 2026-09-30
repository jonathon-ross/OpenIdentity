package org.openidentity.delegation;

import org.junit.jupiter.api.Test;
import org.openidentity.cbor.DeterministicCborWriter;
import org.openidentity.crypto.Sha256Multihash;
import org.openidentity.core.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class Oi014Oi016UseTimeTest {
 record Raw(byte[] b){}
 static byte[] h(String s){try{return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));}catch(Exception e){throw new RuntimeException(e);}}
 static byte[] seq(int s,int n){byte[] b=new byte[n];for(int i=0;i<n;i++)b[i]=(byte)(s+i);return b;}
 static byte[] mh(String s){return Sha256Multihash.digest(s.getBytes(StandardCharsets.UTF_8));}
 static void put(DeterministicCborWriter w,Object x){if(x instanceof Integer i)w.writeUnsigned(i);else if(x instanceof Long l)w.writeUnsigned(l);else if(x instanceof byte[] b)w.writeByteString(b);else if(x instanceof Raw r)w.writeEncoded(r.b());else throw new IllegalArgumentException();}
 static byte[] map(Object... kv){DeterministicCborWriter w=new DeterministicCborWriter();w.writeMapHeader(kv.length/2);for(int i=0;i<kv.length;i+=2){w.writeUnsigned((Integer)kv[i]);put(w,kv[i+1]);}return w.toByteArray();}
 static byte[] arr(Raw... xs){DeterministicCborWriter w=new DeterministicCborWriter();w.writeArrayHeader(xs.length);for(Raw x:xs)w.writeEncoded(x.b());return w.toByteArray();}
 static byte[] principal(byte[] id){return map(1,1,2,id);}
 static byte[] cap(byte[] ph,String id,String rc){byte[] pr=map(1,1,2,ph),cr=map(1,new Raw(pr),2,id.getBytes(StandardCharsets.UTF_8));return rc==null?map(1,new Raw(cr)):map(1,new Raw(cr),2,rc.getBytes(StandardCharsets.UTF_8));}
 static byte[] grant(byte[] root,byte[] issuer,byte[] delegate,byte[] capability,long exp,byte[] parent,String nonce){
  if(parent==null)return map(1,1,2,root,3,new Raw(principal(issuer)),4,new Raw(principal(delegate)),5,new Raw(arr(new Raw(capability))),7,exp,9,h(nonce));
  return map(1,1,2,root,3,new Raw(principal(issuer)),4,new Raw(principal(delegate)),5,new Raw(arr(new Raw(capability))),7,exp,8,parent,9,h(nonce));
 }
 static byte[] token(byte[] registry,byte[] parent,byte[] child,byte[] assertionId){
  byte[] pe=map(1,parent,2,Sha256Multihash.digest(parent)),ce=map(1,child,2,Sha256Multihash.digest(child));
  byte[] evidence=map(1,1,2,registry,3,new Raw(arr(new Raw(pe),new Raw(ce))));
  return map(1,1,2,new Raw(evidence),3,assertionId);
 }

 static class ExactProfile implements CapabilityProfile {
  final byte[] hash;ExactProfile(byte[] hash){this.hash=hash.clone();}
  public byte[] profileHash(){return hash.clone();}public long maximumGrantLifetimeSeconds(){return 7200;}public int maximumDelegationDepth(){return 3;}
  public boolean permitsChild(List<CapabilityRef> parent,List<CapabilityRef> child){
   Set<String> p=new HashSet<>();for(CapabilityRef x:parent)p.add(new String(x.capabilityId(),StandardCharsets.UTF_8)+":"+(x.resourceConstraint()==null?"":new String(x.resourceConstraint(),StandardCharsets.UTF_8)));
   for(CapabilityRef x:child){String id=new String(x.capabilityId(),StandardCharsets.UTF_8),rc=x.resourceConstraint()==null?"":new String(x.resourceConstraint(),StandardCharsets.UTF_8);
    if(id.equals("records.read")&&rc.equals("tenant/alpha/record/42")&&p.contains("records.read:tenant/alpha/*"))continue;
    if(!p.contains(id+":"+rc))return false;}return true;
  }
  public List<Object> effectiveCapabilities(List<CapabilityRef> xs){return new ArrayList<>(xs);}
 }

 record Fixture(byte[] registry,byte[] root,byte[] d1,byte[] d2,byte[] parent,byte[] child,byte[] token,byte[] ph,long now,byte[] rootStateHash){}
 Fixture fixture(){
  long now=2_002_010_000L;byte[] root=seq(96,32),d1=seq(128,32),d2=seq(160,32),ph=mh("OI-016 DS02 capability profile");
  byte[] parentCap=cap(ph,"records.read","tenant/alpha/*");
  byte[] parent=grant(root,root,d1,parentCap,now+2600,null,"OpenIdentity OI-016 DS02 parent nonce");
  byte[] childCap=cap(ph,"records.read","tenant/alpha/record/42");
  byte[] child=grant(root,d1,d2,childCap,now+800,Sha256Multihash.digest(parent),"OpenIdentity OI-016 DS02 child nonce");
  byte[] registry="openidentity:test:oi016:ds02".getBytes(StandardCharsets.UTF_8),aid=mh("actor assertion"),state=mh("root state");
  return new Fixture(registry,root,d1,d2,parent,child,token(registry,parent,child,aid),ph,now,state);
 }
 Oi016Verifier verifier(Fixture f,int parentStatus,long generation,boolean recordsAvailable,CapabilityProfile profile){
  Map<String,RegisteredGrantState> rs=new HashMap<>();
  if(recordsAvailable){rs.put(HexFormat.of().formatHex(Sha256Multihash.digest(f.parent())),new RegisteredGrantState(f.registry(),Sha256Multihash.digest(f.parent()),1,parentStatus,f.rootStateHash(),7,f.now()-100));
   rs.put(HexFormat.of().formatHex(Sha256Multihash.digest(f.child())),new RegisteredGrantState(f.registry(),Sha256Multihash.digest(f.child()),1,RegisteredGrantState.ACTIVE,f.rootStateHash(),7,f.now()-100));}
  RegisteredGrantStateResolver rr=(reg,id)->rs.get(HexFormat.of().formatHex(id));
  RootDelegationStateResolver roots=id->new RootDelegationState(f.root(),f.rootStateHash(),true,generation);
  CapabilityProfileResolver profiles=hash->Arrays.equals(hash,f.ph())?profile:null;
  var g=new DefaultOi014GrantVerifier(rr,roots,profiles);return new Oi016Verifier(g,profiles);
 }

 @Test void ds02StylePathVerifiesAgainstAuthoritativeState(){
  Fixture f=fixture();var out=verifier(f,RegisteredGrantState.ACTIVE,7,true,new ExactProfile(f.ph())).verify(f.token(),f.now());
  assertArrayEquals(f.root(),out.rootGrantor());assertArrayEquals(f.d2(),out.terminalDelegate());assertEquals(f.now()+800,out.earliestExpiresAt());
 }
 @Test void revokedAncestorFailsClosed(){
  Fixture f=fixture();VerificationException e=assertThrows(VerificationException.class,()->verifier(f,RegisteredGrantState.REVOKED,7,true,new ExactProfile(f.ph())).verify(f.token(),f.now()));
  assertEquals(VerificationError.NOT_CURRENTLY_USABLE,e.error());
 }
 @Test void rootGenerationInvalidationFailsClosed(){
  Fixture f=fixture();VerificationException e=assertThrows(VerificationException.class,()->verifier(f,RegisteredGrantState.ACTIVE,8,true,new ExactProfile(f.ph())).verify(f.token(),f.now()));
  assertEquals(VerificationError.NOT_CURRENTLY_USABLE,e.error());
 }
 @Test void unavailableRegistryStateFailsClosed(){
  Fixture f=fixture();VerificationException e=assertThrows(VerificationException.class,()->verifier(f,RegisteredGrantState.ACTIVE,7,false,new ExactProfile(f.ph())).verify(f.token(),f.now()));
  assertEquals(VerificationError.STATE_UNAVAILABLE,e.error());
 }
 @Test void capabilityExpansionFailsClosed(){
  Fixture f=fixture();CapabilityProfile deny=new ExactProfile(f.ph()){public boolean permitsChild(List<CapabilityRef> p,List<CapabilityRef> c){return false;}};
  VerificationException e=assertThrows(VerificationException.class,()->verifier(f,RegisteredGrantState.ACTIVE,7,true,deny).verify(f.token(),f.now()));
  assertEquals(VerificationError.AUTHORITY_NOT_PERMITTED,e.error());
 }
}
