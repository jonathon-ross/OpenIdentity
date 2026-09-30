package org.openidentity.auth;

import org.openidentity.cbor.StrictCborReader;
import java.util.*;

public final class Oi015Codec {
 private Oi015Codec(){}
 public static SecuredAuthenticationAssertion decode(byte[] exactSecuredBytes){
  try{
   StrictCborReader r=new StrictCborReader(exactSecuredBytes);expect(r.readMapHeader(),2);
   expect(r.readUnsigned(),1);int start=r.position();AuthenticationAssertion a=assertion(r);int end=r.position();
   // assertion() parsed from the same reader; replace its exact bytes with the exact nested CBOR slice.
   a=new AuthenticationAssertion(a.version(),a.identity(),a.stateHash(),a.authenticationGeneration(),a.audience(),a.purpose(),a.issuedAt(),a.expiresAt(),a.nonce(),a.contextHash(),r.slice(start,end));
   expect(r.readUnsigned(),2);long n=r.readArrayHeader();if(n<1||n>64)fail();
   List<AuthenticationProof> proofs=new ArrayList<>();byte[] prev=null;
   for(int i=0;i<n;i++){expect(r.readMapHeader(),2);expect(r.readUnsigned(),1);byte[] id=r.readByteString();expect(r.readUnsigned(),2);byte[] sig=r.readByteString();
    if(id.length<1||id.length>64||sig.length!=64||(prev!=null&&Arrays.compareUnsigned(prev,id)>=0))fail();prev=id;proofs.add(new AuthenticationProof(id,sig));}
   if(!r.done())fail();return new SecuredAuthenticationAssertion(a,proofs);
  }catch(RuntimeException e){if(e instanceof IllegalArgumentException)throw e;throw new IllegalArgumentException("INVALID_AUTHENTICATION_ASSERTION",e);}
 }
 private static AuthenticationAssertion assertion(StrictCborReader r){
  expect(r.readMapHeader(),10);expect(r.readUnsigned(),1);long v=r.readUnsigned();if(v!=1)fail();
  expect(r.readUnsigned(),2);byte[] identity=r.readByteString();if(identity.length!=32)fail();
  expect(r.readUnsigned(),3);byte[] stateHash=r.readByteString();if(stateHash.length!=34)fail();
  expect(r.readUnsigned(),4);long gen=r.readUnsigned();
  expect(r.readUnsigned(),5);byte[] audience=r.readByteString();if(audience.length<1||audience.length>1024)fail();
  expect(r.readUnsigned(),6);String purpose=r.readTextString();if(!purpose.matches("^[a-z0-9](?:[a-z0-9._-]{0,253}[a-z0-9])?$"))fail();
  expect(r.readUnsigned(),7);long issued=r.readUnsigned();expect(r.readUnsigned(),8);long expires=r.readUnsigned();
  expect(r.readUnsigned(),9);byte[] nonce=r.readByteString();if(nonce.length<16||nonce.length>64)fail();
  expect(r.readUnsigned(),10);byte[] context=r.readByteString();if(context.length!=34)fail();
  return new AuthenticationAssertion((int)v,identity,stateHash,gen,audience,purpose,issued,expires,nonce,context,new byte[0]);
 }
 private static void expect(long a,long b){if(a!=b)fail();}
 private static void fail(){throw new IllegalArgumentException("INVALID_AUTHENTICATION_ASSERTION");}
}
