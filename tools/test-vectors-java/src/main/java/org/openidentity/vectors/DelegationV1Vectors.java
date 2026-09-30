package org.openidentity.vectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;

public final class DelegationV1Vectors {
    private static byte[] sha(byte[] b)throws Exception{return MessageDigest.getInstance("SHA-256").digest(b);}
    private static byte[] mh(byte[] b)throws Exception{byte[] d=sha(b),o=new byte[34];o[0]=0x12;o[1]=0x20;System.arraycopy(d,0,o,2,32);return o;}
    private static byte[] seq(int start,int n){byte[] b=new byte[n];for(int i=0;i<n;i++)b[i]=(byte)(start+i);return b;}
    private static void require(String n,boolean ok){if(!ok)throw new AssertionError(n);System.out.println("  "+n+": PASS");}
    private static byte[] map(Object... kv){DeterministicCborWriter w=new DeterministicCborWriter();w.writeMapHeader(kv.length/2);for(int i=0;i<kv.length;i+=2){w.writeUnsigned((Integer)kv[i]);write(w,kv[i+1]);}return w.toByteArray();}
    private static byte[] arr(Object... xs){DeterministicCborWriter w=new DeterministicCborWriter();w.writeArrayHeader(xs.length);for(Object x:xs)write(w,x);return w.toByteArray();}
    private static void write(DeterministicCborWriter w,Object x){
        if(x==null)w.writeNull(); else if(x instanceof Integer i)w.writeUnsigned(i); else if(x instanceof Long l)w.writeUnsigned(l);
        else if(x instanceof String s)w.writeTextString(s); else if(x instanceof byte[] b)w.writeByteString(b);
        else if(x instanceof Enc e)w.writeEncoded(e.b); else throw new IllegalArgumentException(x.getClass().toString());
    }
    private record Enc(byte[] b){}
    private static Enc E(byte[] b){return new Enc(b);}
    private static byte[] method(byte[] pub){return map(1,1,3,new Signed(-8),4,new Signed(-1),6,pub);}
    private record Signed(long v){}
    private static void writeSignedMap(DeterministicCborWriter w,Object x){}
    private static byte[] method2(byte[] pub){
        DeterministicCborWriter w=new DeterministicCborWriter();w.writeMapHeader(4);
        w.writeUnsigned(1);w.writeUnsigned(1);w.writeUnsigned(3);w.writeSigned(-8);w.writeUnsigned(4);w.writeSigned(-1);w.writeUnsigned(6);w.writeByteString(pub);return w.toByteArray();
    }
    private static byte[] policy(byte[] mid,byte[] m){return map(1,1,2,E(arr(E(map(1,mid,2,E(m))))));}
    private static String hx(JsonNode v,String n){return v.path(n).asText();}
    public static void main(String[] args)throws Exception{
        Path file=Path.of("..","..","test-vectors","generated","delegation-v1.json");
        JsonNode rootJson=new ObjectMapper().readTree(Files.readString(file));
        require("suite specification","OpenIdentity OI-014 DelegationGrant v1".equals(rootJson.path("suite").asText()));
        require("draft status","DRAFT-NON-NORMATIVE".equals(rootJson.path("status").asText()));
        JsonNode v=rootJson.path("vectors").get(0);require("DG01 id","DG01".equals(v.path("id").asText()));

        byte[] registry="openidentity:test:oi014:dg01".getBytes(StandardCharsets.UTF_8), root=seq(0,32), delegate=seq(32,32), mid=seq(0,16);
        Ed25519Support ed=new Ed25519Support(sha("OpenIdentity OI-014 DG01 delegation Ed25519 seed".getBytes(StandardCharsets.UTF_8)));
        byte[] m=method2(ed.publicKey()),dp=policy(mid,m);

        byte[] descriptor=map(1,1,2,"openidentity.test.exact-capability",3,1,4,E(arr("document.read".getBytes(StandardCharsets.UTF_8))),5,3600,6,4);
        byte[] ph=mh(descriptor);
        require("DG01 ProfileDescriptor bytes",hx(v,"profileDescriptorBytesHex").equals(Hex.encode(descriptor)));
        require("DG01 ProfileHash",hx(v,"profileHashHex").equals(Hex.encode(ph)));

        byte[] pref=map(1,1,2,ph),cref=map(1,E(pref),2,"document.read".getBytes(StandardCharsets.UTF_8)),dc=map(1,E(cref));
        byte[] issuer=map(1,1,2,root),del=map(1,1,2,delegate);
        byte[] nonce=sha("OpenIdentity OI-014 DG01 nonce".getBytes(StandardCharsets.UTF_8));
        byte[] grant=map(1,1,2,root,3,E(issuer),4,E(del),5,E(arr(E(dc))),7,2000003600L,9,nonce);
        byte[] gid=mh(grant);
        require("DG01 GrantBytes",hx(v,"grantBytesHex").equals(Hex.encode(grant)));require("DG01 GrantId",hx(v,"grantIdHex").equals(Hex.encode(gid)));

        byte[] state=map(1,3,2,root,3,7,4,1,5,E(dp),8,E(map(1,0)),9,E(map(1,4,2,E(dp))));
        byte[] sh=mh(state);
        require("DG01 current StateBytes",hx(v,"currentStateBytesHex").equals(Hex.encode(state)));require("DG01 current StateHash",hx(v,"currentStateHashHex").equals(Hex.encode(sh)));

        byte[] signing=arr("OpenIdentity Delegation Grant",1,registry,grant,sh,4,mid);
        byte[] sig=ed.sign(signing);
        require("DG01 registration signing bytes",hx(v,"registrationSigningBytesHex").equals(Hex.encode(signing)));
        require("DG01 signature",hx(v,"registrationSignatureHex").equals(Hex.encode(sig)));require("DG01 signature verifies",ed.verify(signing,sig));

        byte[] proof=map(1,mid,2,sig),request=map(1,registry,2,E(grant),3,sh,4,4,5,E(arr(E(proof))));
        require("DG01 registration request bytes",hx(v,"registrationRequestBytesHex").equals(Hex.encode(request)));
        byte[] record=map(1,registry,2,gid,3,1,4,null,5,1,6,sh,7,4,8,2000000000L),rh=mh(record);
        require("DG01 RecordBytes",hx(v,"recordBytesHex").equals(Hex.encode(record)));require("DG01 RecordHash",hx(v,"recordHashHex").equals(Hex.encode(rh)));
        System.out.println("\n============================================");
        System.out.println("OI-014 DELEGATION v1 JAVA DG01 VERIFIED");
        System.out.println("============================================");
    }
}
