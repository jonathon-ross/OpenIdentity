package org.openidentity.bootstrap;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.openidentity.auth.*;
import java.nio.file.*;import java.util.*;

public final class SignOi015 {
 private SignOi015(){}
 public static void main(String[] args)throws Exception{
  Map<String,String> a=parse(args);Map<String,String> key=read(Path.of(req(a,"key")));if(!"authentication".equals(key.get("purpose")))throw new IllegalArgumentException("authentication key required");
  var h=HexFormat.of();byte[] identity=h.parseHex(key.get("identity")),method=h.parseHex(key.get("methodId")),seed=h.parseHex(key.get("ed25519Seed")),stateHash=h.parseHex(req(a,"state-hash")),aud=h.parseHex(req(a,"audience")),nonce=h.parseHex(req(a,"nonce")),context=h.parseHex(req(a,"context-hash"));
  long gen=Long.parseLong(req(a,"generation")),now=Long.parseLong(a.getOrDefault("issued-at",Long.toString(System.currentTimeMillis()/1000))),expires=now+Long.parseLong(a.getOrDefault("lifetime","120"));
  var base=new AuthenticationAssertion(1,identity,stateHash,gen,aud,req(a,"purpose"),now,expires,nonce,context,new byte[0]);byte[] exact=Oi015Codec.encodeAssertion(base);var assertion=new AuthenticationAssertion(1,identity,stateHash,gen,aud,base.purpose(),now,expires,nonce,context,exact);
  byte[] signing=AuthenticationAssertionCodec.signingBytes(assertion,method);var s=new Ed25519Signer();s.init(true,new Ed25519PrivateKeyParameters(seed,0));s.update(signing,0,signing.length);byte[] sig=s.generateSignature();
  System.out.println(h.formatHex(Oi015Codec.encode(assertion,List.of(new AuthenticationProof(method,sig)))));
 }
 private static Map<String,String> read(Path p)throws Exception{Map<String,String> m=new HashMap<>();for(String l:Files.readAllLines(p)){int x=l.indexOf('=');if(x>0)m.put(l.substring(0,x),l.substring(x+1));}return m;}
 private static Map<String,String> parse(String[] a){Map<String,String> m=new HashMap<>();for(int i=0;i<a.length;i++){if(!a[i].startsWith("--")||i+1>=a.length)throw new IllegalArgumentException("expected --name value");m.put(a[i++].substring(2),a[i]);}return m;}private static String req(Map<String,String> m,String k){String v=m.get(k);if(v==null)throw new IllegalArgumentException("missing --"+k);return v;}
}
