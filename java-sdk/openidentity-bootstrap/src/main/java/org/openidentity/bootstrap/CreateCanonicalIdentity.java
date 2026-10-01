package org.openidentity.bootstrap;

import org.openidentity.core.*;
import java.nio.charset.StandardCharsets;import java.nio.file.*;import java.security.SecureRandom;import java.util.*;

public final class CreateCanonicalIdentity {
 private CreateCanonicalIdentity(){}
 public static void main(String[] args)throws Exception{
  Map<String,String> a=parse(args);Path stateDir=Path.of(a.getOrDefault("state-dir","openidentity-state")),secretDir=Path.of(a.getOrDefault("secret-dir","openidentity-secrets"));
  var created=CreateIdentityV2.create(new SecureRandom());var h=HexFormat.of();String identity=h.formatHex(created.identity());
  var state=new CanonicalIdentityState(created.identity(),created.stateHash(),true,new CanonicalAuthenticationAuthority(0,1,List.of(new CanonicalAuthenticationMethod(created.authenticationMethodId(),created.authenticationPublicKey()))));
  new FileCanonicalIdentityStateRepository(stateDir).save(state);
  Files.createDirectories(secretDir);Path controller=secretDir.resolve(identity+".controller.key"),authentication=secretDir.resolve(identity+".authentication.key");
  writeSecret(controller,"controller",created.identity(),created.controllerMethodId(),created.controllerSeed(),created.controllerPublicKey());
  try{writeSecret(authentication,"authentication",created.identity(),created.authenticationMethodId(),created.authenticationSeed(),created.authenticationPublicKey());}
  catch(Exception e){Files.deleteIfExists(controller);throw e;}
  System.out.println("OpenIdentity development identity created");
  System.out.println("Identity: "+identity);System.out.println("StateHash: "+h.formatHex(created.stateHash()));System.out.println("State version: 3");System.out.println("Authentication generation: 0");System.out.println("Authentication threshold: 1");
  System.out.println("Canonical public state: "+stateDir.toAbsolutePath().resolve(identity+".oidstate"));
  System.out.println("Controller authenticator: "+controller.toAbsolutePath());System.out.println("Authentication authenticator: "+authentication.toAbsolutePath());
 }
 private static void writeSecret(Path out,String purpose,byte[] id,byte[] method,byte[] seed,byte[] pub)throws Exception{
  var h=HexFormat.of();String s="version=1\npurpose="+purpose+"\nidentity="+h.formatHex(id)+"\nmethodId="+h.formatHex(method)+"\ned25519PublicKey="+h.formatHex(pub)+"\ned25519Seed="+h.formatHex(seed)+"\n";
  Files.writeString(out,s,StandardCharsets.US_ASCII,StandardOpenOption.CREATE_NEW);try{Files.setPosixFilePermissions(out,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));}catch(UnsupportedOperationException ignored){}
 }
 private static Map<String,String> parse(String[] args){Map<String,String> m=new LinkedHashMap<>();for(int i=0;i<args.length;i++){if(!args[i].startsWith("--")||i+1>=args.length)throw new IllegalArgumentException("expected --name value");String k=args[i++].substring(2);if(!Set.of("state-dir","secret-dir").contains(k)||m.put(k,args[i])!=null)throw new IllegalArgumentException("invalid/duplicate --"+k);}return m;}
}
