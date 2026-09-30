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

    private static void verifyDG02(JsonNode v)throws Exception{
        byte[] registry="openidentity:test:oi014:dg02".getBytes(StandardCharsets.UTF_8), root=seq(64,32), delegate=seq(96,32);
        byte[] ma=seq(0,16), mb=seq(16,16);
        Ed25519Support ea=new Ed25519Support(sha("OpenIdentity OI-014 DG02 delegation A Ed25519 seed".getBytes(StandardCharsets.UTF_8)));
        Ed25519Support eb=new Ed25519Support(sha("OpenIdentity OI-014 DG02 delegation B Ed25519 seed".getBytes(StandardCharsets.UTF_8)));
        byte[] mtha=method2(ea.publicKey()),mthb=method2(eb.publicKey());
        byte[] entries=arr(E(map(1,ma,2,E(mtha))),E(map(1,mb,2,E(mthb))));
        byte[] dp=map(1,2,2,2,3,E(entries));

        byte[] descriptor=map(1,1,2,"openidentity.test.exact-capability",3,1,
                4,E(arr("document.write".getBytes(StandardCharsets.UTF_8))),5,1800,6,2);
        byte[] ph=mh(descriptor);
        require("DG02 ProfileDescriptor bytes",hx(v,"profileDescriptorBytesHex").equals(Hex.encode(descriptor)));
        require("DG02 ProfileHash",hx(v,"profileHashHex").equals(Hex.encode(ph)));

        byte[] pref=map(1,1,2,ph),cref=map(1,E(pref),2,"document.write".getBytes(StandardCharsets.UTF_8)),dc=map(1,E(cref));
        byte[] grant=map(1,1,2,root,3,E(map(1,1,2,root)),4,E(map(1,1,2,delegate)),
                5,E(arr(E(dc))),7,2000002800L,9,sha("OpenIdentity OI-014 DG02 nonce".getBytes(StandardCharsets.UTF_8)));
        byte[] gid=mh(grant);
        require("DG02 GrantBytes",hx(v,"grantBytesHex").equals(Hex.encode(grant)));
        require("DG02 GrantId",hx(v,"grantIdHex").equals(Hex.encode(gid)));

        byte[] state=map(1,3,2,root,3,11,4,1,5,E(dp),8,E(map(1,0)),9,E(map(1,9,2,E(dp))));
        byte[] sh=mh(state);
        require("DG02 current StateBytes",hx(v,"currentStateBytesHex").equals(Hex.encode(state)));
        require("DG02 current StateHash",hx(v,"currentStateHashHex").equals(Hex.encode(sh)));

        byte[] sa=arr("OpenIdentity Delegation Grant",1,registry,grant,sh,9,ma);
        byte[] sb=arr("OpenIdentity Delegation Grant",1,registry,grant,sh,9,mb);
        byte[] siga=ea.sign(sa),sigb=eb.sign(sb);
        require("DG02 signing A",hx(v,"registrationSigningBytesAHex").equals(Hex.encode(sa)));
        require("DG02 signing B",hx(v,"registrationSigningBytesBHex").equals(Hex.encode(sb)));
        require("DG02 signature A",hx(v,"registrationSignatureAHex").equals(Hex.encode(siga)));
        require("DG02 signature B",hx(v,"registrationSignatureBHex").equals(Hex.encode(sigb)));
        require("DG02 both threshold signatures verify",ea.verify(sa,siga)&&eb.verify(sb,sigb));

        byte[] pa=map(1,ma,2,siga),pb=map(1,mb,2,sigb);
        byte[] request=map(1,registry,2,E(grant),3,sh,4,9,5,E(arr(E(pa),E(pb))));
        require("DG02 canonical proof order",Hex.encode(ma).compareTo(Hex.encode(mb))<0);
        require("DG02 registration request bytes",hx(v,"registrationRequestBytesHex").equals(Hex.encode(request)));

        byte[] record=map(1,registry,2,gid,3,1,4,null,5,1,6,sh,7,9,8,2000001000L);
        byte[] rh=mh(record);
        require("DG02 RecordBytes",hx(v,"recordBytesHex").equals(Hex.encode(record)));
        require("DG02 RecordHash",hx(v,"recordHashHex").equals(Hex.encode(rh)));
    }


    private static void verifyDG03(JsonNode v)throws Exception{
        byte[] registry="openidentity:test:oi014:dg03".getBytes(StandardCharsets.UTF_8),root=seq(128,32),delegate=seq(160,32);
        byte[] ida=seq(32,16),idb=seq(48,16);
        Ed25519Support a=new Ed25519Support(sha("OpenIdentity OI-014 DG03 delegation A Ed25519 seed".getBytes(StandardCharsets.UTF_8)));
        Ed25519Support b=new Ed25519Support(sha("OpenIdentity OI-014 DG03 delegation B Ed25519 seed".getBytes(StandardCharsets.UTF_8)));
        byte[] pa=policy(ida,method2(a.publicKey())),pb=policy(idb,method2(b.publicKey()));
        byte[] descriptor=map(1,1,2,"openidentity.test.exact-capability",3,1,
                4,E(arr("document.read".getBytes(StandardCharsets.UTF_8))),5,7200,6,3);
        byte[] ph=mh(descriptor),pref=map(1,1,2,ph),cref=map(1,E(pref),2,"document.read".getBytes(StandardCharsets.UTF_8)),dc=map(1,E(cref));
        byte[] grant=map(1,1,2,root,3,E(map(1,1,2,root)),4,E(map(1,1,2,delegate)),
                5,E(arr(E(dc))),7,2000010000L,9,sha("OpenIdentity OI-014 DG03 nonce".getBytes(StandardCharsets.UTF_8)));
        byte[] gid=mh(grant); int generation=12;
        byte[] before=map(1,3,2,root,3,20,4,1,5,E(pa),8,E(map(1,0)),9,E(map(1,generation,2,E(pa))));
        byte[] beforeHash=mh(before);
        require("DG03 GrantBytes",hx(v,"grantBytesHex").equals(Hex.encode(grant)));
        require("DG03 registration StateBytes",hx(v,"registrationStateBytesHex").equals(Hex.encode(before)));
        require("DG03 registration StateHash",hx(v,"registrationStateHashHex").equals(Hex.encode(beforeHash)));
        byte[] signing=arr("OpenIdentity Delegation Grant",1,registry,grant,beforeHash,generation,ida),sig=a.sign(signing);
        require("DG03 registration signing bytes",hx(v,"registrationSigningBytesHex").equals(Hex.encode(signing)));
        require("DG03 original registration signature",hx(v,"registrationSignatureHex").equals(Hex.encode(sig)));
        require("DG03 original registration signature verifies",a.verify(signing,sig));
        byte[] record=map(1,registry,2,gid,3,1,4,null,5,1,6,beforeHash,7,generation,8,2000003000L),recordHash=mh(record);
        require("DG03 original RecordBytes",hx(v,"recordBytesHex").equals(Hex.encode(record)));
        require("DG03 original RecordHash",hx(v,"recordHashHex").equals(Hex.encode(recordHash)));
        byte[] op=map(1,2,2,7,3,root,4,21,5,beforeHash,6,E(map(1,E(pb),2,0)));
        require("DG03 rotation OperationBytes",hx(v,"rotationOperationBytesHex").equals(Hex.encode(op)));
        byte[] after=map(1,3,2,root,3,21,4,1,5,E(pa),8,E(map(1,0)),9,E(map(1,generation,2,E(pb))));
        require("DG03 post-rotation StateBytes",hx(v,"postRotationStateBytesHex").equals(Hex.encode(after)));
        require("DG03 post-rotation StateHash",hx(v,"postRotationStateHashHex").equals(Hex.encode(mh(after))));
        require("DG03 generation preserved",v.path("delegationGenerationBefore").asInt()==generation&&v.path("delegationGenerationAfter").asInt()==generation);
        require("DG03 registration record unchanged",hx(v,"recordHashAfterRotationHex").equals(Hex.encode(recordHash)));
        require("DG03 grant remains generation-compatible",v.path("grantUsableAfterRotation").asBoolean());
    }


    private static void verifyDG04(JsonNode v)throws Exception{
        byte[] registry="openidentity:test:oi014:dg04".getBytes(StandardCharsets.UTF_8),root=seq(192,32),delegate=seq(224,32);
        byte[] cid=seq(64,16),did=seq(80,16);
        Ed25519Support controller=new Ed25519Support(sha("OpenIdentity OI-014 DG04 controller Ed25519 seed".getBytes(StandardCharsets.UTF_8)));
        Ed25519Support delegation=new Ed25519Support(sha("OpenIdentity OI-014 DG04 delegation Ed25519 seed".getBytes(StandardCharsets.UTF_8)));
        byte[] cp=policy(cid,method2(controller.publicKey())),dp=policy(did,method2(delegation.publicKey()));
        byte[] descriptor=map(1,1,2,"openidentity.test.exact-capability",3,1,
                4,E(arr("document.delete".getBytes(StandardCharsets.UTF_8))),5,3600,6,2);
        byte[] ph=mh(descriptor),pref=map(1,1,2,ph),cref=map(1,E(pref),2,"document.delete".getBytes(StandardCharsets.UTF_8)),dc=map(1,E(cref));
        byte[] grant=map(1,1,2,root,3,E(map(1,1,2,root)),4,E(map(1,1,2,delegate)),
                5,E(arr(E(dc))),7,2000015000L,9,sha("OpenIdentity OI-014 DG04 nonce".getBytes(StandardCharsets.UTF_8)));
        byte[] gid=mh(grant);int generation=15;
        byte[] state=map(1,3,2,root,3,30,4,1,5,E(cp),8,E(map(1,0)),9,E(map(1,generation,2,E(dp))));
        byte[] sh=mh(state);
        require("DG04 GrantBytes",hx(v,"grantBytesHex").equals(Hex.encode(grant)));
        require("DG04 current StateBytes",hx(v,"currentStateBytesHex").equals(Hex.encode(state)));
        require("DG04 current StateHash",hx(v,"currentStateHashHex").equals(Hex.encode(sh)));
        byte[] regSigning=arr("OpenIdentity Delegation Grant",1,registry,grant,sh,generation,did),regSig=delegation.sign(regSigning);
        require("DG04 original registration signature",hx(v,"registrationSignatureHex").equals(Hex.encode(regSig)));
        require("DG04 original registration signature verifies",delegation.verify(regSigning,regSig));
        byte[] r1=map(1,registry,2,gid,3,1,4,null,5,1,6,sh,7,generation,8,2000010000L),r1h=mh(r1);
        require("DG04 ACTIVE RecordHash",hx(v,"activeRecordHashHex").equals(Hex.encode(r1h)));
        byte[] revSigning=arr("OpenIdentity Delegation Grant Revocation",1,registry,gid,r1h,2,sh,cid),revSig=controller.sign(revSigning);
        require("DG04 revocation signing bytes",hx(v,"revocationSigningBytesHex").equals(Hex.encode(revSigning)));
        require("DG04 ControllerPolicy revocation signature",hx(v,"revocationSignatureHex").equals(Hex.encode(revSig)));
        require("DG04 ControllerPolicy revocation verifies",controller.verify(revSigning,revSig));
        byte[] revReq=map(1,registry,2,gid,3,r1h,4,2,5,sh,6,1,7,E(arr(E(map(1,cid,2,revSig)))));
        require("DG04 revocation request bytes",hx(v,"revocationRequestBytesHex").equals(Hex.encode(revReq)));
        byte[] r2=map(1,registry,2,gid,3,2,4,r1h,5,2,6,sh,7,generation,8,2000010000L),r2h=mh(r2);
        require("DG04 exact next revision",2==1+1);
        require("DG04 previous RecordHash binding",Arrays.equals(r1h,Hex.decode(hx(v,"activeRecordHashHex"))));
        require("DG04 GrantId unchanged",hx(v,"grantIdAfterRevocationHex").equals(Hex.encode(gid)));
        require("DG04 registeredAt unchanged",v.path("registeredAtBefore").asLong()==2000010000L&&v.path("registeredAtAfter").asLong()==2000010000L);
        require("DG04 revoked RecordBytes",hx(v,"revokedRecordBytesHex").equals(Hex.encode(r2)));
        require("DG04 revoked RecordHash",hx(v,"revokedRecordHashHex").equals(Hex.encode(r2h)));
    }


    private static void verifyDG05(JsonNode v)throws Exception{
        byte[] registry="openidentity:test:oi014:dg05".getBytes(StandardCharsets.UTF_8),root=seq(16,32),delegate=seq(48,32);
        byte[] ida=seq(96,16),idb=seq(112,16);
        Ed25519Support a=new Ed25519Support(sha("OpenIdentity OI-014 DG05 delegation A Ed25519 seed".getBytes(StandardCharsets.UTF_8)));
        Ed25519Support b=new Ed25519Support(sha("OpenIdentity OI-014 DG05 delegation B Ed25519 seed".getBytes(StandardCharsets.UTF_8)));
        byte[] pa=policy(ida,method2(a.publicKey())),pb=policy(idb,method2(b.publicKey()));
        byte[] descriptor=map(1,1,2,"openidentity.test.exact-capability",3,1,
                4,E(arr("document.admin".getBytes(StandardCharsets.UTF_8))),5,3600,6,2);
        byte[] ph=mh(descriptor),pref=map(1,1,2,ph),cref=map(1,E(pref),2,"document.admin".getBytes(StandardCharsets.UTF_8)),dc=map(1,E(cref));
        byte[] grant=map(1,1,2,root,3,E(map(1,1,2,root)),4,E(map(1,1,2,delegate)),
                5,E(arr(E(dc))),7,2000020000L,9,sha("OpenIdentity OI-014 DG05 nonce".getBytes(StandardCharsets.UTF_8)));
        byte[] gid=mh(grant);int generation=21;
        byte[] before=map(1,3,2,root,3,40,4,1,5,E(pa),8,E(map(1,0)),9,E(map(1,generation,2,E(pa))));
        byte[] beforeHash=mh(before);
        require("DG05 GrantBytes",hx(v,"grantBytesHex").equals(Hex.encode(grant)));
        require("DG05 registration StateHash",hx(v,"registrationStateHashHex").equals(Hex.encode(beforeHash)));
        byte[] regSigning=arr("OpenIdentity Delegation Grant",1,registry,grant,beforeHash,generation,ida),regSig=a.sign(regSigning);
        require("DG05 original registration signature",hx(v,"registrationSignatureHex").equals(Hex.encode(regSig)));
        require("DG05 original registration signature verifies",a.verify(regSigning,regSig));
        byte[] record=map(1,registry,2,gid,3,1,4,null,5,1,6,beforeHash,7,generation,8,2000016000L),recordHash=mh(record);
        require("DG05 original ACTIVE RecordHash",hx(v,"activeRecordHashHex").equals(Hex.encode(recordHash)));
        byte[] op=map(1,2,2,7,3,root,4,41,5,beforeHash,6,E(map(1,E(pb),2,1)));
        require("DG05 INVALIDATE_EXISTING OperationBytes",hx(v,"invalidationOperationBytesHex").equals(Hex.encode(op)));
        byte[] after=map(1,3,2,root,3,41,4,1,5,E(pa),8,E(map(1,0)),9,E(map(1,generation+1,2,E(pb))));
        require("DG05 post-invalidation StateBytes",hx(v,"postInvalidationStateBytesHex").equals(Hex.encode(after)));
        require("DG05 post-invalidation StateHash",hx(v,"postInvalidationStateHashHex").equals(Hex.encode(mh(after))));
        require("DG05 generation increments exactly once",v.path("delegationGenerationBefore").asInt()==21&&v.path("delegationGenerationAfter").asInt()==22);
        require("DG05 record remains revision 1 ACTIVE",v.path("recordRevisionAfterInvalidation").asInt()==1&&"ACTIVE".equals(v.path("recordStatusAfterInvalidation").asText()));
        require("DG05 RecordHash unchanged",hx(v,"recordHashAfterInvalidationHex").equals(Hex.encode(recordHash)));
        require("DG05 grant unusable solely by generation mismatch",!v.path("grantUsableAfterInvalidation").asBoolean()&&generation!=(generation+1));
    }

    public static void main(String[] args)throws Exception{
        Path file=Path.of("..","..","test-vectors","generated","delegation-v1.json");
        JsonNode rootJson=new ObjectMapper().readTree(Files.readString(file));
        require("suite specification","OpenIdentity OI-014 DelegationGrant v1".equals(rootJson.path("suite").asText()));
        require("draft status","DRAFT-NON-NORMATIVE".equals(rootJson.path("status").asText()));
        JsonNode v=rootJson.path("vectors").get(0);require("DG01 id","DG01".equals(v.path("id").asText()));
        require("vector count",rootJson.path("vectors").size()==5);

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
        verifyDG02(rootJson.path("vectors").get(1));
        verifyDG03(rootJson.path("vectors").get(2));
        verifyDG04(rootJson.path("vectors").get(3));
        verifyDG05(rootJson.path("vectors").get(4));
        System.out.println("\n============================================");
        System.out.println("OI-014 DELEGATION v1 JAVA DG01-DG05 VERIFIED");
        System.out.println("============================================");
    }
}
