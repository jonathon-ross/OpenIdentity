package org.openidentity.delegation;

import org.openidentity.cbor.StrictCborReader;
import org.openidentity.crypto.Sha256Multihash;
import java.util.*;

public final class Oi014Codec {
 private Oi014Codec(){}
 public static DelegationGrant decodeGrant(byte[] exact){
  StrictCborReader r=new StrictCborReader(exact);long n=r.readMapHeader();if(n<7||n>9)fail();
  expect(r.readUnsigned(),1);expect(r.readUnsigned(),1);expect(r.readUnsigned(),2);byte[] root=r.readByteString();if(root.length!=32)fail();
  expect(r.readUnsigned(),3);Principal issuer=principal(r);expect(r.readUnsigned(),4);Principal delegate=principal(r);
  expect(r.readUnsigned(),5);List<CapabilityRef> caps=capabilities(r);
  Long nb=null;long label=r.readUnsigned();if(label==6){nb=r.readUnsigned();label=r.readUnsigned();}
  if(label!=7)fail();long exp=r.readUnsigned();byte[] parent=null;label=r.readUnsigned();if(label==8){parent=r.readByteString();Sha256Multihash.requireValid(parent);label=r.readUnsigned();}
  if(label!=9)fail();byte[] nonce=r.readByteString();if(nonce.length!=32||!r.done())fail();
  if(nb!=null&&nb>=exp)fail();return new DelegationGrant(exact,Sha256Multihash.digest(exact),root,issuer,delegate,caps,nb,exp,parent,nonce);
 }
 private static Principal principal(StrictCborReader r){
  long n=r.readMapHeader();if(n==2){expect(r.readUnsigned(),1);expect(r.readUnsigned(),1);expect(r.readUnsigned(),2);byte[] id=r.readByteString();if(id.length!=32)fail();return new OpenIdentityPrincipal(id);}
  if(n==3){expect(r.readUnsigned(),1);expect(r.readUnsigned(),2);expect(r.readUnsigned(),2);byte[] id=r.readByteString();if(id.length<1||id.length>256)fail();expect(r.readUnsigned(),3);
   expect(r.readMapHeader(),2);expect(r.readUnsigned(),1);expect(r.readUnsigned(),2);expect(r.readUnsigned(),2);byte[] ph=r.readByteString();Sha256Multihash.requireValid(ph);return new ProfilePrincipal(id,ph);}
  fail();return null;
 }
 private static List<CapabilityRef> capabilities(StrictCborReader r){
  long n=r.readArrayHeader();if(n<1||n>4096)fail();List<CapabilityRef> out=new ArrayList<>();byte[] prev=null;
  for(int i=0;i<n;i++){int start=r.position();long m=r.readMapHeader();if(m<1||m>2)fail();expect(r.readUnsigned(),1);
   expect(r.readMapHeader(),2);expect(r.readUnsigned(),1);expect(r.readMapHeader(),2);expect(r.readUnsigned(),1);expect(r.readUnsigned(),1);expect(r.readUnsigned(),2);byte[] ph=r.readByteString();Sha256Multihash.requireValid(ph);
   expect(r.readUnsigned(),2);byte[] cid=r.readByteString();if(cid.length<1||cid.length>128)fail();byte[] rc=null;
   if(m==2){expect(r.readUnsigned(),2);rc=r.readByteString();if(rc.length<1||rc.length>4096)fail();}
   byte[] encoded=r.slice(start,r.position());if(prev!=null&&Arrays.compareUnsigned(prev,encoded)>=0)fail();prev=encoded;out.add(new CapabilityRef(ph,cid,rc));}
  return List.copyOf(out);
 }
 private static void expect(long a,long b){if(a!=b)fail();}private static void fail(){throw new IllegalArgumentException("INVALID_DELEGATION_GRANT");}
}
