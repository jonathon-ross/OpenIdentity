package org.openidentity.vectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

public final class AuthenticationAssertionV1Vectors {
    static final ObjectMapper JSON=new ObjectMapper();
    static void require(String n,boolean v){if(!v)throw new AssertionError(n);System.out.println("  "+n+": PASS");}
    static byte[] sha(byte[] b)throws Exception{return MessageDigest.getInstance("SHA-256").digest(b);}
    static byte[] mh(byte[] b)throws Exception{byte[] d=sha(b),o=new byte[34];o[0]=0x12;o[1]=0x20;System.arraycopy(d,0,o,2,32);return o;}
    static byte[] seq(int start,int n){byte[] b=new byte[n];for(int i=0;i<n;i++)b[i]=(byte)(start+i);return b;}
    record E(byte[] b){}
    static E E(byte[] b){return new E(b);}
    static byte[] map(Object... kv){
        DeterministicCborWriter w=new DeterministicCborWriter();
        w.writeMapHeader(kv.length/2);
        for(int i=0;i<kv.length;i+=2){w.writeUnsigned((Integer)kv[i]);write(w,kv[i+1]);}
        return w.toByteArray();
    }
    static byte[] arr(Object... xs){
        DeterministicCborWriter w=new DeterministicCborWriter();
        w.writeArrayHeader(xs.length);
        for(Object x:xs)write(w,x);
        return w.toByteArray();
    }
    static void write(DeterministicCborWriter w,Object x){
        if(x==null)w.writeNull();
        else if(x instanceof Integer i)w.writeUnsigned(i);
        else if(x instanceof Long l)w.writeUnsigned(l);
        else if(x instanceof String t)w.writeTextString(t);
        else if(x instanceof byte[] bytes)w.writeByteString(bytes);
        else if(x instanceof E e)w.writeEncoded(e.b);
        else throw new IllegalArgumentException(x.getClass().toString());
    }
    static byte[] method(byte[] pub){
        DeterministicCborWriter w=new DeterministicCborWriter();w.writeMapHeader(4);
        w.writeUnsigned(1);w.writeUnsigned(1);
        w.writeUnsigned(3);w.writeSigned(-8);
        w.writeUnsigned(4);w.writeSigned(-1);
        w.writeUnsigned(6);w.writeByteString(pub);
        return w.toByteArray();
    }
    static byte[] singlePolicy(byte[] id,byte[] pub){return map(1,1,2,E(arr(E(map(1,id,2,E(method(pub)))))));}
    static byte[] thresholdPolicy(byte[][] ids,byte[][] pubs,int threshold){
        Integer[] ix=new Integer[ids.length];for(int i=0;i<ix.length;i++)ix[i]=i;
        Arrays.sort(ix,(a,b)->Arrays.compareUnsigned(ids[a],ids[b]));
        Object[] entries=new Object[ix.length];
        for(int j=0;j<ix.length;j++){int i=ix[j];entries[j]=E(map(1,ids[i],2,E(method(pubs[i]))));}
        return map(1,2,2,threshold,3,E(arr(entries)));
    }
    static final class Key{
        final Ed25519PrivateKeyParameters p;
        Key(String label)throws Exception{p=new Ed25519PrivateKeyParameters(sha(label.getBytes(StandardCharsets.UTF_8)),0);}
        byte[] pub(){return p.generatePublicKey().getEncoded();}
        byte[] sign(byte[] msg){Ed25519Signer s=new Ed25519Signer();s.init(true,p);s.update(msg,0,msg.length);return s.generateSignature();}
        boolean verify(byte[] msg,byte[] sig){Ed25519Signer s=new Ed25519Signer();s.init(false,p.generatePublicKey());s.update(msg,0,msg.length);return s.verifySignature(sig);}
    }
    static byte[] hex(String s){return java.util.HexFormat.of().parseHex(s);}
    static String hx(byte[] b){return java.util.HexFormat.of().formatHex(b);}

    static void verifyAA01(JsonNode v)throws Exception{
        byte[] identity=seq(0,32),mid=seq(32,16);Key auth=new Key("OpenIdentity OI-015 AA01 authentication seed");
        byte[] ap=singlePolicy(mid,auth.pub());
        byte[] cid=seq(48,16);Key ctrl=new Key("OpenIdentity OI-015 AA01 controller seed");byte[] cp=singlePolicy(cid,ctrl.pub());
        byte[] state=map(1,3,2,identity,3,21,4,1,5,E(cp),8,E(map(1,7,2,E(ap))),9,E(map(1,0)));byte[] sh=mh(state);
        require("AA01 StateBytes",v.path("stateBytesHex").asText().equals(hx(state)));
        require("AA01 StateHash",v.path("stateHashHex").asText().equals(hx(sh)));
        byte[] ctx="OpenIdentity OI-015 AA01 test context v1".getBytes(StandardCharsets.UTF_8);
        byte[] assertion=map(1,1,2,identity,3,sh,4,7,5,"https://verifier.example.test".getBytes(StandardCharsets.UTF_8),
                6,"openidentity.authentication",7,2001000000L,8,2001000240L,9,seq(64,32),10,mh(ctx));
        require("AA01 AssertionBytes",v.path("assertionBytesHex").asText().equals(hx(assertion)));
        require("AA01 AssertionId",v.path("assertionIdHex").asText().equals(hx(mh(assertion))));
        byte[] signing=arr("OpenIdentity Authentication Assertion",1,assertion,mid),sig=hex(v.path("signatureHex").asText());
        require("AA01 signing bytes",v.path("signingBytesHex").asText().equals(hx(signing)));
        require("AA01 AuthenticationPolicy signature verifies",auth.verify(signing,sig));
        byte[] secured=map(1,E(assertion),2,E(arr(E(map(1,mid,2,sig)))));
        require("AA01 secured assertion bytes",v.path("securedAssertionBytesHex").asText().equals(hx(secured)));
    }

    static void verifyAA02(JsonNode v)throws Exception{
        byte[] identity=seq(96,32),aid=seq(16,16),bid=seq(32,16),cid=seq(48,16);
        Key a=new Key("OpenIdentity OI-015 AA02 auth A seed"),b=new Key("OpenIdentity OI-015 AA02 auth B seed"),c=new Key("OpenIdentity OI-015 AA02 auth C seed");
        byte[] ap=thresholdPolicy(new byte[][]{cid,aid,bid},new byte[][]{c.pub(),a.pub(),b.pub()},2);
        byte[] ctrlid=seq(64,16);Key ctrl=new Key("OpenIdentity OI-015 AA02 controller seed");byte[] cp=singlePolicy(ctrlid,ctrl.pub());
        byte[] state=map(1,3,2,identity,3,34,4,1,5,E(cp),8,E(map(1,12,2,E(ap))),9,E(map(1,0)));byte[] sh=mh(state);
        require("AA02 StateBytes",v.path("stateBytesHex").asText().equals(hx(state)));
        require("AA02 StateHash",v.path("stateHashHex").asText().equals(hx(sh)));
        byte[] ctx="OpenIdentity OI-015 AA02 threshold context".getBytes(StandardCharsets.UTF_8);
        byte[] assertion=map(1,1,2,identity,3,sh,4,12,5,"threshold-verifier".getBytes(StandardCharsets.UTF_8),
                6,"openidentity.authentication",7,2001001000L,8,2001001180L,9,seq(128,32),10,mh(ctx));
        require("AA02 AssertionBytes",v.path("assertionBytesHex").asText().equals(hx(assertion)));
        require("AA02 AssertionId",v.path("assertionIdHex").asText().equals(hx(mh(assertion))));
        byte[] asign=arr("OpenIdentity Authentication Assertion",1,assertion,aid);
        byte[] csign=arr("OpenIdentity Authentication Assertion",1,assertion,cid);
        byte[] asig=hex(v.path("signatureAHex").asText()),csig=hex(v.path("signatureCHex").asText());
        require("AA02 signature A verifies",a.verify(asign,asig));require("AA02 signature C verifies",c.verify(csign,csig));
        require("AA02 generated order intentionally noncanonical","C".equals(v.path("generatedProofOrder").get(0).asText()));
        require("AA02 canonical proof order",Arrays.compareUnsigned(aid,cid)<0);
        byte[] secured=map(1,E(assertion),2,E(arr(E(map(1,aid,2,asig)),E(map(1,cid,2,csig)))));
        require("AA02 secured assertion bytes",v.path("securedAssertionBytesHex").asText().equals(hx(secured)));
    }


    static void verifyAA03(JsonNode v)throws Exception{
        byte[] identity=seq(160,32),mid=seq(80,16);Key auth=new Key("OpenIdentity OI-015 AA03 authentication seed");
        byte[] ap=singlePolicy(mid,auth.pub());
        byte[] ctrlid=seq(96,16);Key ctrl=new Key("OpenIdentity OI-015 AA03 controller seed");byte[] cp=singlePolicy(ctrlid,ctrl.pub());
        byte[] state=map(1,3,2,identity,3,55,4,1,5,E(cp),8,E(map(1,19,2,E(ap))),9,E(map(1,0)));byte[] sh=mh(state);
        require("AA03 StateBytes",v.path("stateBytesHex").asText().equals(hx(state)));require("AA03 StateHash",v.path("stateHashHex").asText().equals(hx(sh)));
        long issued=2001002000L,expires=issued+300L;byte[] ctx="OpenIdentity OI-015 AA03 exact lifetime boundary".getBytes(StandardCharsets.UTF_8);
        byte[] assertion=map(1,1,2,identity,3,sh,4,19,5,"lifetime-boundary-verifier".getBytes(StandardCharsets.UTF_8),
                6,"openidentity.authentication",7,issued,8,expires,9,seq(192,32),10,mh(ctx));
        require("AA03 AssertionBytes",v.path("assertionBytesHex").asText().equals(hx(assertion)));require("AA03 AssertionId",v.path("assertionIdHex").asText().equals(hx(mh(assertion))));
        require("AA03 exact 300-second lifetime",expires-issued==300L);
        byte[] signing=arr("OpenIdentity Authentication Assertion",1,assertion,mid),sig=hex(v.path("signatureHex").asText());
        require("AA03 signature verifies",auth.verify(signing,sig));
        byte[] secured=map(1,E(assertion),2,E(arr(E(map(1,mid,2,sig)))));
        require("AA03 secured assertion bytes",v.path("securedAssertionBytesHex").asText().equals(hx(secured)));
    }

    static Path findVectorFile()throws Exception{
        Path dir=Paths.get("").toAbsolutePath().normalize();
        for(int i=0;i<8 && dir!=null;i++,dir=dir.getParent()){
            Path p=dir.resolve("test-vectors").resolve("generated").resolve("authentication-assertion-v1.json");
            if(Files.isRegularFile(p))return p;
        }
        throw new NoSuchFileException("Could not locate repository test-vectors/generated/authentication-assertion-v1.json from "+Paths.get("").toAbsolutePath());
    }

    public static void main(String[] args)throws Exception{
        Path p=findVectorFile();
        System.out.println("Using vectors: "+p);
        JsonNode d=JSON.readTree(Files.readString(p));
        require("suite specification","OpenIdentity OI-015 Authentication Assertion v1".equals(d.path("specification").asText()));
        require("draft status","DRAFT-NON-NORMATIVE".equals(d.path("status").asText()));
        require("vector count",d.path("vectors").size()==3);
        verifyAA01(d.path("vectors").get(0));verifyAA02(d.path("vectors").get(1));verifyAA03(d.path("vectors").get(2));
        System.out.println("\n============================================");
        System.out.println("OI-015 AUTHENTICATION ASSERTION v1 JAVA AA01-AA03 VERIFIED");
        System.out.println("============================================");
    }
}
