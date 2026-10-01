package org.openidentity.bootstrap;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.openidentity.core.*;
import java.nio.charset.StandardCharsets;import java.nio.file.*;import java.util.*;

public final class ImportCanonicalIdentity {
 private ImportCanonicalIdentity(){}
 public static void main(String[] args)throws Exception{
  Map<String,String> a=parse(args);var h=HexFormat.of();
  byte[] identity=h.parseHex(req(a,"identity")),stateHash=h.parseHex(req(a,"state-hash")),methodId=h.parseHex(req(a,"method-id")),publicKey=h.parseHex(req(a,"public-key"));
  long generation=Long.parseLong(a.getOrDefault("generation","1"));int threshold=Integer.parseInt(a.getOrDefault("threshold","1"));
  Path stateDir=Path.of(req(a,"state-dir"));
  if(a.containsKey("private-seed")){
   byte[] seed=h.parseHex(a.get("private-seed"));if(seed.length!=32)throw new IllegalArgumentException("private seed must be 32 bytes");
   byte[] derived=new Ed25519PrivateKeyParameters(seed,0).generatePublicKey().getEncoded();if(!java.security.MessageDigest.isEqual(derived,publicKey))throw new IllegalArgumentException("private seed does not match public key");
   Path out=Path.of(req(a,"authenticator-file"));writePrivate(out,identity,methodId,seed);
  }
  var state=new CanonicalIdentityState(identity,stateHash,true,new CanonicalAuthenticationAuthority(generation,threshold,List.of(new CanonicalAuthenticationMethod(methodId,publicKey))));
  new FileCanonicalIdentityStateRepository(stateDir).save(state);
  System.out.println("Identity: "+h.formatHex(identity));System.out.println("StateHash: "+h.formatHex(stateHash));System.out.println("Authentication generation: "+generation);System.out.println("Canonical public state: "+stateDir.toAbsolutePath());
  if(a.containsKey("private-seed"))System.out.println("Private authenticator: "+Path.of(a.get("authenticator-file")).toAbsolutePath());
 }
 private static void writePrivate(Path out,byte[] identity,byte[] methodId,byte[] seed)throws Exception{
  if(out.getParent()!=null)Files.createDirectories(out.getParent());String s="version=1\nidentity="+HexFormat.of().formatHex(identity)+"\nmethodId="+HexFormat.of().formatHex(methodId)+"\ned25519Seed="+HexFormat.of().formatHex(seed)+"\n";
  Files.writeString(out,s,StandardCharsets.US_ASCII,StandardOpenOption.CREATE_NEW);
  try{Files.setPosixFilePermissions(out,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));}catch(UnsupportedOperationException ignored){}
 }
 private static Map<String,String> parse(String[] args){Map<String,String> m=new LinkedHashMap<>();for(int i=0;i<args.length;i++){if(!args[i].startsWith("--")||i+1>=args.length)throw new IllegalArgumentException("expected --name value");String k=args[i++].substring(2);if(m.put(k,args[i])!=null)throw new IllegalArgumentException("duplicate "+k);}return m;}
 private static String req(Map<String,String> m,String k){String v=m.get(k);if(v==null||v.isBlank())throw new IllegalArgumentException("missing --"+k);return v;}
}
