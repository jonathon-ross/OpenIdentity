package org.openidentity.oidc;

import org.openidentity.cbor.DeterministicCborWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public final class ExternalOidcBindingV1 {
 public static final int VERSION=1;
 private static final String DOMAIN="OpenIdentity External OIDC Binding";
 private ExternalOidcBindingV1(){}

 public record Binding(byte[] identity,String issuer,String subject,String clientId,long createdAt,Long expiresAt,long authenticationGeneration){
  public Binding{
   Objects.requireNonNull(identity);Objects.requireNonNull(issuer);Objects.requireNonNull(subject);Objects.requireNonNull(clientId);
   if(identity.length!=32)throw new IllegalArgumentException("identity");
   if(issuer.isEmpty()||subject.isEmpty()||clientId.isEmpty())throw new IllegalArgumentException("text");
   identity=identity.clone();
   if(createdAt<0||authenticationGeneration<0||(expiresAt!=null&&expiresAt<0))throw new IllegalArgumentException("uint64");
  }
  @Override public byte[] identity(){return identity.clone();}
 }

 public static byte[] encode(Binding b){
  var w=new DeterministicCborWriter();w.writeMapHeader(8);
  u(w,1);u(w,VERSION);u(w,2);w.writeByteString(b.identity());
  u(w,3);w.writeTextString(b.issuer());u(w,4);w.writeTextString(b.subject());
  u(w,5);w.writeTextString(b.clientId());u(w,6);u(w,b.createdAt());
  u(w,7);if(b.expiresAt()==null)w.writeEncoded(new byte[]{(byte)0xf6});else u(w,b.expiresAt());
  u(w,8);u(w,b.authenticationGeneration());return w.toByteArray();
 }

 public static byte[] bindingId(Binding b){
  byte[] bb=encode(b);var w=new DeterministicCborWriter();w.writeArrayHeader(3);
  w.writeTextString(DOMAIN);u(w,VERSION);w.writeByteString(bb);return multihash(w.toByteArray());
 }

 public static byte[] encodeContext(int action,Binding b,byte[] challenge,byte[] bindingId){
  if(action!=1&&action!=2)throw new IllegalArgumentException("action");
  Objects.requireNonNull(challenge);if(challenge.length<16||challenge.length>128)throw new IllegalArgumentException("challenge");
  if(action==1&&bindingId!=null)throw new IllegalArgumentException("bind bindingId");
  if(action==2&&(bindingId==null||bindingId.length!=34))throw new IllegalArgumentException("revoke bindingId");
  var w=new DeterministicCborWriter();w.writeMapHeader(action==2?11:10);
  u(w,1);u(w,VERSION);u(w,2);u(w,action);u(w,3);w.writeByteString(b.identity());
  u(w,4);w.writeTextString(b.issuer());u(w,5);w.writeTextString(b.subject());u(w,6);w.writeTextString(b.clientId());
  u(w,7);w.writeByteString(challenge);u(w,8);u(w,b.authenticationGeneration());u(w,9);u(w,b.createdAt());
  u(w,10);if(b.expiresAt()==null)w.writeEncoded(new byte[]{(byte)0xf6});else u(w,b.expiresAt());
  if(action==2){u(w,11);w.writeByteString(bindingId);}
  return w.toByteArray();
 }
 public static byte[] contextHash(byte[] contextBytes){return multihash(contextBytes);}
 private static void u(DeterministicCborWriter w,long v){w.writeUnsigned(v);}
 private static byte[] multihash(byte[] bytes){
  try{byte[] d=MessageDigest.getInstance("SHA-256").digest(bytes),out=new byte[34];out[0]=0x12;out[1]=0x20;System.arraycopy(d,0,out,2,32);return out;}
  catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}
 }
}
