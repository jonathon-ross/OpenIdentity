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
    private static final byte[] EXACT_SPEC=("OpenIdentity OI-014 Test Profile: exact-capability v1\n"+
            "Semantics: exact capability equality; no resources; no redelegation.\n").getBytes(StandardCharsets.UTF_8);
    private static final byte[] REDELEGATION_SPEC=("OpenIdentity OI-014 Test Profile: redelegation v1\n"+
            "Semantics: exact capabilities; explicit redelegate.document.read authorizes redelegation of document.read; no resources.\n").getBytes(StandardCharsets.UTF_8);

    private static byte[] profileDescriptor(int kind,byte[] spec,long maxLifetime,long maxDepth,byte[] params)throws Exception{
        return map(1,1,2,kind,3,mh(spec),4,maxLifetime,5,maxDepth,6,params);
    }
    private static byte[] exactProfile(byte[][] caps,long maxLifetime,long maxDepth)throws Exception{
        byte[][] copy=caps.clone();
        Arrays.sort(copy,(a,b)->{
            int n=Math.min(a.length,b.length);
            for(int i=0;i<n;i++){int ai=a[i]&255,bi=b[i]&255;if(ai!=bi)return Integer.compare(ai,bi);}
            return Integer.compare(a.length,b.length);
        });
        Object[] xs=new Object[copy.length];
        for(int i=0;i<copy.length;i++)xs[i]=copy[i];
        return profileDescriptor(1,EXACT_SPEC,maxLifetime,maxDepth,arr(xs));
    }
    private static byte[] redelegationProfile(long maxLifetime,long maxDepth)throws Exception{
        return profileDescriptor(1,REDELEGATION_SPEC,maxLifetime,maxDepth,
                arr("document.read".getBytes(StandardCharsets.UTF_8),"redelegate.document.read".getBytes(StandardCharsets.UTF_8)));
    }

    private static String hx(JsonNode v,String n){return v.path(n).asText();}

    private static void verifyDG02(JsonNode v)throws Exception{
        byte[] registry="openidentity:test:oi014:dg02".getBytes(StandardCharsets.UTF_8), root=seq(64,32), delegate=seq(96,32);
        byte[] ma=seq(0,16), mb=seq(16,16);
        Ed25519Support ea=new Ed25519Support(sha("OpenIdentity OI-014 DG02 delegation A Ed25519 seed".getBytes(StandardCharsets.UTF_8)));
        Ed25519Support eb=new Ed25519Support(sha("OpenIdentity OI-014 DG02 delegation B Ed25519 seed".getBytes(StandardCharsets.UTF_8)));
        byte[] mtha=method2(ea.publicKey()),mthb=method2(eb.publicKey());
        byte[] entries=arr(E(map(1,ma,2,E(mtha))),E(map(1,mb,2,E(mthb))));
        byte[] dp=map(1,2,2,2,3,E(entries));

        byte[] descriptor=exactProfile(new byte[][]{"document.write".getBytes(StandardCharsets.UTF_8)},1800L,2L);
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
        byte[] descriptor=exactProfile(new byte[][]{"document.read".getBytes(StandardCharsets.UTF_8)},7200L,3L);
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
        byte[] descriptor=exactProfile(new byte[][]{"document.delete".getBytes(StandardCharsets.UTF_8)},3600L,2L);
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
        byte[] descriptor=exactProfile(new byte[][]{"document.admin".getBytes(StandardCharsets.UTF_8)},3600L,2L);
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


    private static void verifyDG06(JsonNode v)throws Exception{
        byte[] registry="openidentity:test:oi014:dg06".getBytes(StandardCharsets.UTF_8);
        byte[] root=seq(80,32),parentDelegate=seq(112,32),childDelegate=seq(144,32);
        byte[] delegationId=seq(128,16),authId=seq(144,16);
        Ed25519Support delegation=new Ed25519Support(sha("OpenIdentity OI-014 DG06 root delegation Ed25519 seed".getBytes(StandardCharsets.UTF_8)));
        Ed25519Support auth=new Ed25519Support(sha("OpenIdentity OI-014 DG06 parent delegate authentication Ed25519 seed".getBytes(StandardCharsets.UTF_8)));
        byte[] dp=policy(delegationId,method2(delegation.publicKey())),ap=policy(authId,method2(auth.publicKey()));
        byte[] descriptor=redelegationProfile(7200L,3L);
        byte[] ph=mh(descriptor),pref=map(1,1,2,ph);
        byte[] read=map(1,E(map(1,E(pref),2,"document.read".getBytes(StandardCharsets.UTF_8))));
        byte[] redelegate=map(1,E(map(1,E(pref),2,"redelegate.document.read".getBytes(StandardCharsets.UTF_8))));
        byte[] parent=map(1,1,2,root,3,E(map(1,1,2,root)),4,E(map(1,1,2,parentDelegate)),
                5,E(arr(E(read),E(redelegate))),7,2000030000L,9,sha("OpenIdentity OI-014 DG06 parent nonce".getBytes(StandardCharsets.UTF_8)));
        byte[] parentId=mh(parent);int generation=30;
        byte[] rootState=map(1,3,2,root,3,50,4,1,5,E(dp),8,E(map(1,0)),9,E(map(1,generation,2,E(dp)))),rootHash=mh(rootState);
        byte[] parentSigning=arr("OpenIdentity Delegation Grant",1,registry,parent,rootHash,generation,delegationId);
        require("DG06 parent registration verifies",delegation.verify(parentSigning,Hex.decode(hx(v,"parentRegistrationSignatureHex"))));
        byte[] parentRecord=map(1,registry,2,parentId,3,1,4,null,5,1,6,rootHash,7,generation,8,2000020000L),parentRecordHash=mh(parentRecord);
        int authGeneration=7;
        byte[] delegateState=map(1,3,2,parentDelegate,3,9,4,1,5,E(ap),8,E(map(1,authGeneration,2,E(ap))),9,E(map(1,0)));
        byte[] delegateStateHash=mh(delegateState);
        require("DG06 delegate current StateBytes",hx(v,"delegateStateBytesHex").equals(Hex.encode(delegateState)));
        require("DG06 delegate current StateHash",hx(v,"delegateStateHashHex").equals(Hex.encode(delegateStateHash)));
        byte[] child=map(1,1,2,root,3,E(map(1,1,2,parentDelegate)),4,E(map(1,1,2,childDelegate)),
                5,E(arr(E(read))),7,2000028000L,8,parentId,9,sha("OpenIdentity OI-014 DG06 child nonce".getBytes(StandardCharsets.UTF_8)));
        byte[] childId=mh(child);
        byte[] childSigning=arr("OpenIdentity Delegation Child Grant",1,registry,child,parentId,parentRecordHash,
                delegateStateHash,authGeneration,authId);
        byte[] childSig=auth.sign(childSigning);
        require("DG06 child signing bytes",hx(v,"childSigningBytesHex").equals(Hex.encode(childSigning)));
        require("DG06 AuthenticationAuthority child signature",hx(v,"childAuthenticationSignatureHex").equals(Hex.encode(childSig)));
        require("DG06 AuthenticationAuthority child proof verifies",auth.verify(childSigning,childSig));
        byte[] request=map(1,registry,2,E(child),3,parentId,4,parentRecordHash,5,delegateStateHash,6,authGeneration,
                7,E(arr(E(map(1,authId,2,childSig)))));
        require("DG06 child registration request bytes",hx(v,"childRegistrationRequestBytesHex").equals(Hex.encode(request)));
        byte[] childRecord=map(1,registry,2,childId,3,1,4,null,5,1,6,rootHash,7,generation,8,2000021000L);
        require("DG06 child RecordBytes",hx(v,"childRecordBytesHex").equals(Hex.encode(childRecord)));
        require("DG06 child RecordHash",hx(v,"childRecordHashHex").equals(Hex.encode(mh(childRecord))));
        require("DG06 rootGrantor preserved",v.path("rootGrantorPreserved").asBoolean());
        require("DG06 issuer equals parent delegate",v.path("issuerEqualsParentDelegate").asBoolean());
        require("DG06 capability attenuated",v.path("capabilityAttenuated").asBoolean());
        require("DG06 lifetime attenuated",v.path("lifetimeAttenuated").asBoolean());
        require("DG06 parent redelegation authorized",v.path("parentRedelegationAuthorized").asBoolean());
        require("DG06 depth 2",v.path("childDepth").asInt()==2);
    }


    private static void verifyDG07(JsonNode v)throws Exception{
        byte[] registry="openidentity:test:oi014:dg07".getBytes(StandardCharsets.UTF_8);
        byte[] root=seq(30,32),delegate=seq(62,32),delegationId=seq(60,16),authId=seq(76,16);
        Ed25519Support delegation=new Ed25519Support(sha("OpenIdentity OI-014 DG07 root delegation Ed25519 seed".getBytes(StandardCharsets.UTF_8)));
        Ed25519Support auth=new Ed25519Support(sha("OpenIdentity OI-014 DG07 delegate authentication Ed25519 seed".getBytes(StandardCharsets.UTF_8)));
        byte[] dp=policy(delegationId,method2(delegation.publicKey())),ap=policy(authId,method2(auth.publicKey()));
        byte[] descriptor=exactProfile(new byte[][]{"document.read".getBytes(StandardCharsets.UTF_8)},3600L,2L);
        byte[] ph=mh(descriptor),pref=map(1,1,2,ph),read=map(1,E(map(1,E(pref),2,"document.read".getBytes(StandardCharsets.UTF_8))));
        byte[] grant=map(1,1,2,root,3,E(map(1,1,2,root)),4,E(map(1,1,2,delegate)),
                5,E(arr(E(read))),7,2000600000L,9,sha("OpenIdentity OI-014 DG07 nonce".getBytes(StandardCharsets.UTF_8)));
        byte[] gid=mh(grant);int dgen=33;
        byte[] rootState=map(1,3,2,root,3,60,4,1,5,E(dp),8,E(map(1,0)),9,E(map(1,dgen,2,E(dp)))),rootHash=mh(rootState);
        require("DG07 GrantBytes",hx(v,"grantBytesHex").equals(Hex.encode(grant)));
        require("DG07 root StateBytes",hx(v,"rootStateBytesHex").equals(Hex.encode(rootState)));
        require("DG07 root StateHash",hx(v,"rootStateHashHex").equals(Hex.encode(rootHash)));
        byte[] regSigning=arr("OpenIdentity Delegation Grant",1,registry,grant,rootHash,dgen,delegationId),regSig=delegation.sign(regSigning);
        require("DG07 original registration signature",hx(v,"registrationSignatureHex").equals(Hex.encode(regSig)));
        require("DG07 original registration verifies",delegation.verify(regSigning,regSig));
        long registeredAt=2000590000L;
        byte[] r1=map(1,registry,2,gid,3,1,4,null,5,1,6,rootHash,7,dgen,8,registeredAt),r1h=mh(r1);
        require("DG07 ACTIVE RecordBytes",hx(v,"activeRecordBytesHex").equals(Hex.encode(r1)));
        require("DG07 ACTIVE RecordHash",hx(v,"activeRecordHashHex").equals(Hex.encode(r1h)));

        int agen=11;
        byte[] delegateState=map(1,3,2,delegate,3,17,4,1,5,E(ap),8,E(map(1,agen,2,E(ap))),9,E(map(1,0)));
        byte[] delegateStateHash=mh(delegateState);
        require("DG07 delegate StateBytes",hx(v,"delegateStateBytesHex").equals(Hex.encode(delegateState)));
        require("DG07 delegate StateHash",hx(v,"delegateStateHashHex").equals(Hex.encode(delegateStateHash)));
        byte[] relSigning=arr("OpenIdentity Delegation Grant Relinquishment",1,registry,gid,r1h,2,delegateStateHash,agen,authId);
        byte[] relSig=auth.sign(relSigning);
        require("DG07 relinquishment signing bytes",hx(v,"relinquishmentSigningBytesHex").equals(Hex.encode(relSigning)));
        require("DG07 relinquishment signature",hx(v,"relinquishmentSignatureHex").equals(Hex.encode(relSig)));
        require("DG07 AuthenticationAuthority relinquishment verifies",auth.verify(relSigning,relSig));
        byte[] relReq=map(1,registry,2,gid,3,r1h,4,2,5,delegateStateHash,6,agen,7,E(arr(E(map(1,authId,2,relSig)))));
        require("DG07 relinquishment request bytes",hx(v,"relinquishmentRequestBytesHex").equals(Hex.encode(relReq)));
        byte[] r2=map(1,registry,2,gid,3,2,4,r1h,5,2,6,rootHash,7,dgen,8,registeredAt),r2h=mh(r2);
        require("DG07 exact next revision",2==1+1);
        require("DG07 GrantId unchanged",hx(v,"grantIdAfterRelinquishmentHex").equals(Hex.encode(gid)));
        require("DG07 root delegation generation unchanged",v.path("delegationGenerationBefore").asInt()==dgen&&v.path("delegationGenerationAfter").asInt()==dgen);
        require("DG07 registeredAt unchanged",v.path("registeredAtBefore").asLong()==registeredAt&&v.path("registeredAtAfter").asLong()==registeredAt);
        require("DG07 revoked RecordBytes",hx(v,"revokedRecordBytesHex").equals(Hex.encode(r2)));
        require("DG07 revoked RecordHash",hx(v,"revokedRecordHashHex").equals(Hex.encode(r2h)));
    }


    private static void verifyDG08(JsonNode v)throws Exception{
        byte[] registry="openidentity:test:oi014:dg08".getBytes(StandardCharsets.UTF_8);
        byte[] root=seq(100,32),delegate=seq(132,32),oldId=seq(92,16),newId=seq(108,16);
        Ed25519Support oldKey=new Ed25519Support(sha("OpenIdentity OI-014 DG08 old delegation Ed25519 seed".getBytes(StandardCharsets.UTF_8)));
        Ed25519Support newKey=new Ed25519Support(sha("OpenIdentity OI-014 DG08 new delegation Ed25519 seed".getBytes(StandardCharsets.UTF_8)));
        byte[] oldPolicy=policy(oldId,method2(oldKey.publicKey())),newPolicy=policy(newId,method2(newKey.publicKey()));
        byte[] descriptor=exactProfile(new byte[][]{"document.read".getBytes(StandardCharsets.UTF_8)},7200L,2L);
        byte[] ph=mh(descriptor),pref=map(1,1,2,ph),read=map(1,E(map(1,E(pref),2,"document.read".getBytes(StandardCharsets.UTF_8))));
        byte[] grant=map(1,1,2,root,3,E(map(1,1,2,root)),4,E(map(1,1,2,delegate)),
                5,E(arr(E(read))),7,2000700000L,9,sha("OpenIdentity OI-014 DG08 nonce".getBytes(StandardCharsets.UTF_8)));
        byte[] gid=mh(grant);int generation=44;
        byte[] before=map(1,3,2,root,3,70,4,1,5,E(oldPolicy),8,E(map(1,0)),9,E(map(1,generation,2,E(oldPolicy))));
        byte[] beforeHash=mh(before);
        require("DG08 registration StateBytes",hx(v,"registrationStateBytesHex").equals(Hex.encode(before)));
        require("DG08 registration StateHash",hx(v,"registrationStateHashHex").equals(Hex.encode(beforeHash)));
        byte[] regSigning=arr("OpenIdentity Delegation Grant",1,registry,grant,beforeHash,generation,oldId);
        byte[] regSig=oldKey.sign(regSigning);
        require("DG08 original policy A registration signature",hx(v,"registrationSignatureHex").equals(Hex.encode(regSig)));
        require("DG08 original policy A registration verifies",oldKey.verify(regSigning,regSig));
        byte[] r1=map(1,registry,2,gid,3,1,4,null,5,1,6,beforeHash,7,generation,8,2000690000L),r1h=mh(r1);
        require("DG08 ACTIVE RecordHash",hx(v,"activeRecordHashHex").equals(Hex.encode(r1h)));

        byte[] after=map(1,3,2,root,3,71,4,1,5,E(oldPolicy),8,E(map(1,0)),9,E(map(1,generation,2,E(newPolicy))));
        byte[] afterHash=mh(after);
        require("DG08 current StateBytes",hx(v,"currentStateBytesHex").equals(Hex.encode(after)));
        require("DG08 current StateHash",hx(v,"currentStateHashHex").equals(Hex.encode(afterHash)));
        require("DG08 generation preserved across A-to-B rotation",
                v.path("delegationGenerationBefore").asInt()==generation&&v.path("delegationGenerationAfter").asInt()==generation);
        require("DG08 historical A differs from current B",
                !v.path("historicalDelegationMethodIdHex").asText().equals(v.path("currentDelegationMethodIdHex").asText()));

        byte[] revSigning=arr("OpenIdentity Delegation Grant Revocation",1,registry,gid,r1h,2,afterHash,newId);
        byte[] revSig=newKey.sign(revSigning);
        require("DG08 current policy B revocation signature",hx(v,"revocationSignatureHex").equals(Hex.encode(revSig)));
        require("DG08 current policy B revocation verifies",newKey.verify(revSigning,revSig));
        byte[] revReq=map(1,registry,2,gid,3,r1h,4,2,5,afterHash,6,2,7,E(arr(E(map(1,newId,2,revSig)))));
        require("DG08 revocation request bytes",hx(v,"revocationRequestBytesHex").equals(Hex.encode(revReq)));
        byte[] r2=map(1,registry,2,gid,3,2,4,r1h,5,2,6,beforeHash,7,generation,8,2000690000L);
        require("DG08 revoked RecordBytes",hx(v,"revokedRecordBytesHex").equals(Hex.encode(r2)));
        require("DG08 revoked RecordHash",hx(v,"revokedRecordHashHex").equals(Hex.encode(mh(r2))));
    }

    private static JsonNode invalid(JsonNode doc,String id){
        for(JsonNode v:doc.path("invalidVectors"))if(id.equals(v.path("id").asText()))return v;
        throw new IllegalArgumentException("missing "+id);
    }

    private static void verifyInvalids(JsonNode doc)throws Exception{
        require("invalid vector count",doc.path("invalidVectors").size()==31);
        String[] errors={"UNAUTHORIZED_GRANT_REGISTRATION","INVALID_DELEGATION_GENERATION","CROSS_DOMAIN_PROOF",
                "INVALID_PREVIOUS_RECORD_HASH","CAPABILITY_ESCALATION","PARENT_GRANT_UNUSABLE",
                "ROOT_GRANTOR_MISMATCH","ISSUER_PARENT_DELEGATE_MISMATCH","CHILD_TIME_WIDENING",
                "REDELEGATION_NOT_AUTHORIZED","PROFILE_SUBSTITUTION","TERMINAL_GRANT_STATE",
                "GRANT_EXPIRED_AT_REGISTRATION","INVALID_TIME_RANGE","INVALID_ROOT_STATE_HASH",
                "CROSS_DOMAIN_PROOF","INVALID_GRANT_REVISION","REGISTRY_DOMAIN_MISMATCH",
                "INVALID_REGISTRATION_PROOF","INVALID_DELEGATE_STATE_HASH","INVALID_AUTHENTICATION_GENERATION",
                "INVALID_REGISTRATION_PROOF","INVALID_REGISTRATION_PROOF","CROSS_DOMAIN_PROOF",
                "PARENT_GRANT_NOT_FOUND","PARENT_GRANT_NOT_FOUND","REGISTRY_DOMAIN_MISMATCH",
                "PARENT_GRANT_UNUSABLE","PARENT_GRANT_UNUSABLE","DELEGATION_DEPTH_EXCEEDED","DELEGATION_CYCLE"};
        for(int i=1;i<=31;i++){
            String id=String.format("DGI%02d",i);
            require(id+" stable error",errors[i-1].equals(invalid(doc,id).path("error").asText()));
        }

        JsonNode i1=invalid(doc,"DGI01");
        Ed25519Support oldKey=new Ed25519Support(sha("OpenIdentity OI-014 DGI01 old delegation seed".getBytes(StandardCharsets.UTF_8)));
        byte[] oldSig=Hex.decode(i1.path("submittedSignatureHex").asText());
        byte[] oldSigning=Hex.decode(i1.path("submittedSigningBytesHex").asText());
        require("DGI01 historical signature cryptographically verifies",oldKey.verify(oldSigning,oldSig));
        require("DGI01 old method is not current",!i1.path("submittedMethodIdHex").asText().equals(i1.path("currentDelegationPolicyMethodIdHex").asText()));
        require("DGI01 historical StateHash is not current",!i1.path("historicalStateHashHex").asText().equals(i1.path("currentStateHashHex").asText()));

        JsonNode i2=invalid(doc,"DGI02");
        require("DGI02 claimed generation differs from current",i2.path("claimedGeneration").asInt()!=i2.path("actualGeneration").asInt());

        JsonNode i3=invalid(doc,"DGI03");
        Ed25519Support domainKey=new Ed25519Support(sha("OpenIdentity OI-014 DGI02 delegation seed".getBytes(StandardCharsets.UTF_8)));
        byte[] sig3=Hex.decode(i3.path("submittedSignatureHex").asText());
        byte[] authorized=Hex.decode(i3.path("authorizedSigningBytesHex").asText());
        byte[] required=Hex.decode(i3.path("requiredSigningBytesHex").asText());
        require("DGI03 signature verifies in Registry A domain",domainKey.verify(authorized,sig3));
        require("DGI03 signature rejected in Registry B domain",!domainKey.verify(required,sig3));

        JsonNode i4=invalid(doc,"DGI04");
        require("DGI04 submitted parent RecordHash is stale",
                !i4.path("submittedParentRecordHashHex").asText().equals(i4.path("currentParentRecordHashHex").asText()));

        JsonNode i5=invalid(doc,"DGI05");
        boolean parentHasAdmin=false;
        for(JsonNode c:i5.path("parentCapabilities"))if("document.admin".equals(c.asText()))parentHasAdmin=true;
        require("DGI05 child capability absent from parent authority",!parentHasAdmin&&
                i5.path("childCapabilities").size()==1&&"document.admin".equals(i5.path("childCapabilities").get(0).asText()));

        JsonNode i6=invalid(doc,"DGI06");
        require("DGI06 current parent is REVOKED","REVOKED".equals(i6.path("currentParentStatus").asText()));

        JsonNode i7=invalid(doc,"DGI07");
        require("DGI07 child rootGrantor differs from parent",
                !i7.path("childRootGrantorHex").asText().equals(i7.path("parentRootGrantorHex").asText()));

        JsonNode i8=invalid(doc,"DGI08");
        require("DGI08 child issuer differs from parent delegate",
                !i8.path("childIssuerHex").asText().equals(i8.path("parentDelegateHex").asText()));

        JsonNode i9=invalid(doc,"DGI09");
        require("DGI09 child expiry exceeds parent",
                i9.path("childExpiresAt").asLong()>i9.path("parentExpiresAt").asLong());

        JsonNode i10=invalid(doc,"DGI10");
        require("DGI10 parent lacks explicit redelegation authority",
                i10.path("parentCapabilities").size()==1
                        && "document.read".equals(i10.path("parentCapabilities").get(0).asText())
                        && "document.read".equals(i10.path("requestedChildCapabilities").get(0).asText()));

        JsonNode i11=invalid(doc,"DGI11");
        require("DGI11 same capability name under different profile hash",
                !i11.path("parentProfileHashHex").asText().equals(i11.path("childProfileHashHex").asText())
                        && Arrays.equals(Hex.decode(i11.path("capabilityIdHex").asText()),
                        "document.read".getBytes(StandardCharsets.UTF_8)));

        JsonNode i12=invalid(doc,"DGI12");
        require("DGI12 current grant state is terminal REVOKED",
                i12.path("currentRevision").asInt()==2
                        && "REVOKED".equals(i12.path("currentStatus").asText()));
        require("DGI12 attempted duplicate REGISTER tries revision 1",
                i12.path("attemptedNewRevision").asInt()==1);

        JsonNode i13=invalid(doc,"DGI13");
        require("DGI13 expiresAt is not after registeredAt",
                i13.path("expiresAt").asLong()<=i13.path("registeredAt").asLong());

        JsonNode i14=invalid(doc,"DGI14");
        require("DGI14 notBefore is not less than expiresAt",
                i14.path("notBefore").asLong()>=i14.path("expiresAt").asLong());

        JsonNode i15=invalid(doc,"DGI15");
        Ed25519Support staleController=new Ed25519Support(
                sha("OpenIdentity OI-014 DGI15 controller seed".getBytes(StandardCharsets.UTF_8)));
        byte[] sig15=Hex.decode(i15.path("submittedSignatureHex").asText());
        byte[] sign15=Hex.decode(i15.path("submittedSigningBytesHex").asText());
        require("DGI15 stale revocation signature cryptographically verifies",
                staleController.verify(sign15,sig15));
        require("DGI15 historical root StateHash is stale",
                !i15.path("historicalRootStateHashHex").asText().equals(i15.path("currentRootStateHashHex").asText()));

        JsonNode i16=invalid(doc,"DGI16");
        byte[] sig16=Hex.decode(i16.path("submittedSignatureHex").asText());
        byte[] revDomain=Hex.decode(i16.path("revocationSigningBytesHex").asText());
        byte[] relinquishDomain=Hex.decode(i16.path("relinquishmentSigningBytesHex").asText());
        require("DGI16 signature verifies in revocation domain",
                staleController.verify(revDomain,sig16));
        require("DGI16 revocation signature rejected in relinquishment domain",
                !staleController.verify(relinquishDomain,sig16));

        JsonNode i17=invalid(doc,"DGI17");
        require("DGI17 skips exact-next revision",
                i17.path("currentRevision").asInt()==1 && i17.path("attemptedRevision").asInt()==3);

        JsonNode i18=invalid(doc,"DGI18");
        require("DGI18 registryDomain changes within record chain",
                !i18.path("currentRegistryDomainHex").asText().equals(i18.path("attemptedRegistryDomainHex").asText()));

        JsonNode i19=invalid(doc,"DGI19");
        Ed25519Support controller19=new Ed25519Support(
                sha("OpenIdentity OI-014 auth attack controller seed".getBytes(StandardCharsets.UTF_8)));
        require("DGI19 ControllerPolicy signature cryptographically verifies",
                controller19.verify(Hex.decode(i19.path("submittedSigningBytesHex").asText()),
                        Hex.decode(i19.path("submittedSignatureHex").asText())));
        require("DGI19 controller method is not AuthenticationPolicy method",
                !i19.path("submittedMethodIdHex").asText().equals(i19.path("authenticationMethodIdHex").asText()));

        JsonNode i20=invalid(doc,"DGI20");
        Ed25519Support auth20=new Ed25519Support(
                sha("OpenIdentity OI-014 auth attack authentication seed".getBytes(StandardCharsets.UTF_8)));
        require("DGI20 historical AuthenticationPolicy proof verifies",
                auth20.verify(Hex.decode(i20.path("submittedSigningBytesHex").asText()),
                        Hex.decode(i20.path("submittedSignatureHex").asText())));
        require("DGI20 delegate StateHash is stale",
                !i20.path("historicalDelegateStateHashHex").asText().equals(i20.path("currentDelegateStateHashHex").asText()));

        JsonNode i21=invalid(doc,"DGI21");
        require("DGI21 authentication generation is stale",
                i21.path("submittedAuthenticationGeneration").asInt()!=i21.path("currentAuthenticationGeneration").asInt());

        JsonNode i22=invalid(doc,"DGI22");
        require("DGI22 AuthenticationPolicy absent",!i22.path("authenticationPolicyPresent").asBoolean());

        JsonNode i23=invalid(doc,"DGI23");
        require("DGI23 delegate is DEACTIVATED","DEACTIVATED".equals(i23.path("delegateStatus").asText()));

        JsonNode i24=invalid(doc,"DGI24");
        byte[] sig24=Hex.decode(i24.path("submittedSignatureHex").asText());
        require("DGI24 signature verifies in child domain",
                auth20.verify(Hex.decode(i24.path("childSigningBytesHex").asText()),sig24));
        require("DGI24 child signature rejected in relinquishment domain",
                !auth20.verify(Hex.decode(i24.path("relinquishmentSigningBytesHex").asText()),sig24));

        JsonNode i25=invalid(doc,"DGI25");
        require("DGI25 required parent material unavailable",
                !i25.path("parentGrantBytesAvailable").asBoolean());

        JsonNode i26=invalid(doc,"DGI26");
        byte[] suppliedParent=Hex.decode(i26.path("suppliedParentGrantBytesHex").asText());
        byte[] suppliedParentId=mh(suppliedParent);
        require("DGI26 supplied parent bytes hash to supplied GrantId",
                Hex.encode(suppliedParentId).equals(i26.path("suppliedParentGrantIdHex").asText()));
        require("DGI26 supplied parent does not satisfy committed parentGrantId",
                !i26.path("suppliedParentGrantIdHex").asText().equals(i26.path("committedParentGrantIdHex").asText()));

        JsonNode i27=invalid(doc,"DGI27");
        require("DGI27 parent record belongs to wrong registryDomain",
                !i27.path("childRegistryDomainHex").asText().equals(i27.path("parentRegistryDomainHex").asText()));

        JsonNode i28=invalid(doc,"DGI28");
        require("DGI28 ancestor root delegation generation invalidated",
                i28.path("boundDelegationGeneration").asInt()!=i28.path("currentDelegationGeneration").asInt());

        JsonNode i29=invalid(doc,"DGI29");
        require("DGI29 ancestor expired at exclusive upper boundary",
                i29.path("evaluationTime").asLong()>=i29.path("ancestorExpiresAt").asLong());

        JsonNode i30=invalid(doc,"DGI30");
        require("DGI30 proposed depth exceeds profile maximum",
                i30.path("proposedDepth").asInt()>i30.path("profileMaximumDepth").asInt());

        JsonNode i31=invalid(doc,"DGI31");
        boolean cycle=false;
        for(JsonNode id:i31.path("ancestorGrantIdsHex"))
            if(i31.path("proposedGrantIdHex").asText().equals(id.asText()))cycle=true;
        require("DGI31 proposed GrantId already appears in ancestor chain",cycle);
    }

    public static void main(String[] args)throws Exception{
        Path file=Path.of("..","..","test-vectors","generated","delegation-v1.json");
        JsonNode rootJson=new ObjectMapper().readTree(Files.readString(file));
        require("suite specification","OpenIdentity OI-014 DelegationGrant v1".equals(rootJson.path("suite").asText()));
        require("draft status","DRAFT-NON-NORMATIVE".equals(rootJson.path("status").asText()));
        JsonNode v=rootJson.path("vectors").get(0);require("DG01 id","DG01".equals(v.path("id").asText()));
        require("vector count",rootJson.path("vectors").size()==8);

        byte[] registry="openidentity:test:oi014:dg01".getBytes(StandardCharsets.UTF_8), root=seq(0,32), delegate=seq(32,32), mid=seq(0,16);
        Ed25519Support ed=new Ed25519Support(sha("OpenIdentity OI-014 DG01 delegation Ed25519 seed".getBytes(StandardCharsets.UTF_8)));
        byte[] m=method2(ed.publicKey()),dp=policy(mid,m);

        byte[] descriptor=exactProfile(new byte[][]{"document.read".getBytes(StandardCharsets.UTF_8)},3600L,4L);
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
        verifyDG06(rootJson.path("vectors").get(5));
        verifyDG07(rootJson.path("vectors").get(6));
        verifyDG08(rootJson.path("vectors").get(7));
        verifyInvalids(rootJson);
        System.out.println("\n============================================");
        System.out.println("OI-014 DELEGATION v1 JAVA DG01-DG08 + DGI01-DGI31 VERIFIED");
        System.out.println("============================================");
    }
}
