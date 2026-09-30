package org.openidentity.delegation;

import org.openidentity.cbor.StrictCborReader;
import org.openidentity.crypto.Sha256Multihash;
import java.util.*;

public final class Oi016Codec {
 private Oi016Codec(){}
 public static DelegatedSubjectToken decode(byte[] exactTokenBytes){
  try{
   StrictCborReader r=new StrictCborReader(exactTokenBytes);expect(r.readMapHeader(),3);expect(r.readUnsigned(),1);expect(r.readUnsigned(),1);
   expect(r.readUnsigned(),2);int evidenceStart=r.position();DelegationEvidence e=evidence(r);int evidenceEnd=r.position();
   e=new DelegationEvidence(e.registryDomain(),e.path(),r.slice(evidenceStart,evidenceEnd));
   expect(r.readUnsigned(),3);byte[] aid=r.readByteString();Sha256Multihash.requireValid(aid);if(!r.done())fail();return new DelegatedSubjectToken(e,aid);
  }catch(RuntimeException e){if(e instanceof IllegalArgumentException)throw e;throw new IllegalArgumentException("INVALID_DELEGATED_SUBJECT_TOKEN",e);}
 }
 private static DelegationEvidence evidence(StrictCborReader r){
  expect(r.readMapHeader(),3);expect(r.readUnsigned(),1);expect(r.readUnsigned(),1);expect(r.readUnsigned(),2);byte[] registry=r.readByteString();if(registry.length<1||registry.length>128)fail();
  expect(r.readUnsigned(),3);long n=r.readArrayHeader();if(n<1||n>16)fail();List<GrantEvidence> path=new ArrayList<>();
  for(int i=0;i<n;i++){expect(r.readMapHeader(),2);expect(r.readUnsigned(),1);byte[] gb=r.readByteString();if(gb.length<1||gb.length>65536)fail();
   expect(r.readUnsigned(),2);byte[] gid=r.readByteString();Sha256Multihash.requireValid(gid);if(!Arrays.equals(gid,Sha256Multihash.digest(gb)))throw new IllegalArgumentException("GRANT_ID_MISMATCH");path.add(new GrantEvidence(gb,gid));}
  return new DelegationEvidence(registry,path,new byte[0]);
 }
 private static void expect(long a,long b){if(a!=b)fail();}
 private static void fail(){throw new IllegalArgumentException("INVALID_DELEGATED_SUBJECT_TOKEN");}
}
