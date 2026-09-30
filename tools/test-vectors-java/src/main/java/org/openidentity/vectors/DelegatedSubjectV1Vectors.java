package org.openidentity.vectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public final class DelegatedSubjectV1Vectors {
    static final ObjectMapper JSON=new ObjectMapper();
    static void require(String n,boolean v){if(!v)throw new AssertionError(n);System.out.println("  "+n+": PASS");}
    static byte[] sha(byte[] b)throws Exception{return MessageDigest.getInstance("SHA-256").digest(b);}
    static byte[] mh(byte[] b)throws Exception{byte[] d=sha(b),o=new byte[34];o[0]=0x12;o[1]=0x20;System.arraycopy(d,0,o,2,32);return o;}
    static byte[] seq(int start,int n){byte[] b=new byte[n];for(int i=0;i<n;i++)b[i]=(byte)(start+i);return b;}
    static String hx(byte[] b){return HexFormat.of().formatHex(b);}
    record E(byte[] b){}
    static E E(byte[] b){return new E(b);}
    static void write(DeterministicCborWriter w,Object x){
        if(x instanceof Integer i)w.writeUnsigned(i);
        else if(x instanceof Long l)w.writeUnsigned(l);
        else if(x instanceof String t)w.writeTextString(t);
        else if(x instanceof byte[] b)w.writeByteString(b);
        else if(x instanceof E e)w.writeEncoded(e.b);
        else throw new IllegalArgumentException("Unsupported "+x.getClass());
    }
    static byte[] map(Object... kv){
        DeterministicCborWriter w=new DeterministicCborWriter();w.writeMapHeader(kv.length/2);
        for(int i=0;i<kv.length;i+=2){w.writeUnsigned((Integer)kv[i]);write(w,kv[i+1]);}
        return w.toByteArray();
    }
    static byte[] arr(Object... xs){
        DeterministicCborWriter w=new DeterministicCborWriter();w.writeArrayHeader(xs.length);
        for(Object x:xs)write(w,x);return w.toByteArray();
    }
    static Path findVectorFile()throws Exception{
        Path dir=Paths.get("").toAbsolutePath().normalize();
        for(int i=0;i<8&&dir!=null;i++,dir=dir.getParent()){
            Path p=dir.resolve("test-vectors").resolve("generated").resolve("delegated-subject-v1.json");
            if(Files.isRegularFile(p))return p;
        }
        throw new NoSuchFileException("Could not locate test-vectors/generated/delegated-subject-v1.json");
    }
    static void verifyDS01(JsonNode v)throws Exception{
        byte[] root=seq(0,32),delegate=seq(32,32);
        byte[] profileHash=mh("OI-016 DS01 capability profile".getBytes(StandardCharsets.UTF_8));
        byte[] profileRef=map(1,1,2,profileHash);
        byte[] capRef=map(1,E(profileRef),2,"document.read".getBytes(StandardCharsets.UTF_8));
        byte[] delegatedCap=map(1,E(capRef));
        byte[] rootPrincipal=map(1,1,2,root),delegatePrincipal=map(1,1,2,delegate);
        byte[] nonce=sha("OpenIdentity OI-016 DS01 grant nonce".getBytes(StandardCharsets.UTF_8));
        byte[] grant=map(1,1,2,root,3,E(rootPrincipal),4,E(delegatePrincipal),5,E(arr(E(delegatedCap))),7,2002003600L,9,nonce);
        byte[] gid=mh(grant);
        require("DS01 GrantBytes",v.path("grantBytesHex").asText().equals(hx(grant)));
        require("DS01 GrantId",v.path("grantIdHex").asText().equals(hx(gid)));

        byte[] registry="openidentity:test:oi016:ds01".getBytes(StandardCharsets.UTF_8);
        byte[] grantEvidence=map(1,grant,2,gid);
        byte[] evidence=map(1,1,2,registry,3,E(arr(E(grantEvidence))));
        byte[] eid=mh(evidence);
        require("DS01 DelegationEvidenceBytes",v.path("delegationEvidenceBytesHex").asText().equals(hx(evidence)));
        require("DS01 DelegationEvidenceId",v.path("delegationEvidenceIdHex").asText().equals(hx(eid)));

        byte[] assertion=map(1,1,2,delegate,3,mh("OI-016 DS01 actor state".getBytes(StandardCharsets.UTF_8)),4,5,
                5,"oi016-test-verifier".getBytes(StandardCharsets.UTF_8),6,"openidentity.authentication",
                7,2002000000L,8,2002000120L,9,seq(64,32),10,mh(eid));
        byte[] aid=mh(assertion);
        require("DS01 actor AssertionBytes",v.path("actorAssertionBytesHex").asText().equals(hx(assertion)));
        require("DS01 actorAssertionId",v.path("actorAssertionIdHex").asText().equals(hx(aid)));

        byte[] token=map(1,1,2,E(evidence),3,aid);
        require("DS01 token bytes",v.path("delegatedSubjectTokenBytesHex").asText().equals(hx(token)));
        require("DS01 token id",v.path("delegatedSubjectTokenIdHex").asText().equals(hx(mh(token))));
        require("DS01 actor equals terminal delegate",v.path("terminalDelegateHex").asText().equals(hx(delegate)));
    }

    static void verifyDS02(JsonNode v)throws Exception{
        byte[] root=seq(96,32),d1=seq(128,32),d2=seq(160,32);
        byte[] ph=mh("OI-016 DS02 capability profile".getBytes(StandardCharsets.UTF_8));
        byte[] pr=map(1,1,2,ph),cr=map(1,E(pr),2,"records.read".getBytes(StandardCharsets.UTF_8));
        byte[] rp=map(1,1,2,root),d1p=map(1,1,2,d1),d2p=map(1,1,2,d2);
        byte[] parent=map(1,1,2,root,3,E(rp),4,E(d1p),5,E(arr(E(map(1,E(cr),2,"tenant/alpha/*".getBytes(StandardCharsets.UTF_8))))),
                7,2002013600L,9,sha("OpenIdentity OI-016 DS02 parent nonce".getBytes(StandardCharsets.UTF_8)));
        byte[] pid=mh(parent);
        byte[] child=map(1,1,2,root,3,E(d1p),4,E(d2p),5,E(arr(E(map(1,E(cr),2,"tenant/alpha/record/42".getBytes(StandardCharsets.UTF_8))))),
                7,2002011800L,8,pid,9,sha("OpenIdentity OI-016 DS02 child nonce".getBytes(StandardCharsets.UTF_8)));
        byte[] cid=mh(child);
        require("DS02 parent GrantId",v.path("parentGrantIdHex").asText().equals(hx(pid)));
        require("DS02 child GrantId",v.path("childGrantIdHex").asText().equals(hx(cid)));
        require("DS02 child parentGrantId links parent",v.path("childParentGrantIdHex").asText().equals(hx(pid)));
        require("DS02 child issuer equals parent delegate",v.path("childIssuerHex").asText().equals(v.path("parentDelegateHex").asText())&&v.path("parentDelegateHex").asText().equals(hx(d1)));
        require("DS02 rootGrantor preserved",v.path("rootGrantorHex").asText().equals(hx(root)));
        byte[] evidence=map(1,1,2,"openidentity:test:oi016:ds02".getBytes(StandardCharsets.UTF_8),
                3,E(arr(E(map(1,parent,2,pid)),E(map(1,child,2,cid)))));
        byte[] eid=mh(evidence);
        require("DS02 DelegationEvidenceBytes",v.path("delegationEvidenceBytesHex").asText().equals(hx(evidence)));
        require("DS02 DelegationEvidenceId",v.path("delegationEvidenceIdHex").asText().equals(hx(eid)));
        byte[] actor=map(1,1,2,d2,3,mh("OI-016 DS02 actor state".getBytes(StandardCharsets.UTF_8)),4,11,
                5,"oi016-ds02-verifier".getBytes(StandardCharsets.UTF_8),6,"openidentity.authentication",
                7,2002010000L,8,2002010120L,9,seq(192,32),10,mh(eid));
        byte[] aid=mh(actor);require("DS02 actorAssertionId",v.path("actorAssertionIdHex").asText().equals(hx(aid)));
        require("DS02 actor equals terminal delegate",v.path("terminalDelegateHex").asText().equals(hx(d2)));
        byte[] token=map(1,1,2,E(evidence),3,aid);
        require("DS02 token bytes",v.path("delegatedSubjectTokenBytesHex").asText().equals(hx(token)));
        require("DS02 token id",v.path("delegatedSubjectTokenIdHex").asText().equals(hx(mh(token))));
    }

    public static void main(String[] args)throws Exception{
        Path p=findVectorFile();System.out.println("Using vectors: "+p);
        JsonNode d=JSON.readTree(Files.readString(p));
        require("suite specification","OpenIdentity OI-016 Delegated Subject Token v1".equals(d.path("specification").asText()));
        require("draft status","DRAFT-NON-NORMATIVE".equals(d.path("status").asText()));
        require("vector IDs DS01-DS02",d.path("vectors").size()==2&&"DS01".equals(d.path("vectors").get(0).path("id").asText())&&"DS02".equals(d.path("vectors").get(1).path("id").asText()));
        verifyDS01(d.path("vectors").get(0));verifyDS02(d.path("vectors").get(1));
        System.out.println("\n============================================");
        System.out.println("OI-016 DELEGATED SUBJECT v1 JAVA DS01-DS02 VERIFIED");
        System.out.println("============================================");
    }
}
