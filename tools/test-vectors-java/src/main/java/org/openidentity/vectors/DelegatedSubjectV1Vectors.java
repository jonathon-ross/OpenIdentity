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



    static void verifyDS03to06(JsonNode d)throws Exception{
        JsonNode v3=d.path("vectors").get(2);require("DS03 exact 16-grant hard ceiling",v3.path("pathLength").asInt()==16&&v3.path("grantIdsHex").size()==16);
        Set<String> ids3=new HashSet<>();for(JsonNode x:v3.path("grantIdsHex"))ids3.add(x.asText());require("DS03 no duplicate GrantIds",ids3.size()==16);
        JsonNode v4=d.path("vectors").get(3);require("DS04 16 grants",v4.path("grantCount").asInt()==16);
        require("DS04 evidence within 1 MiB",v4.path("delegationEvidenceLength").asLong()<=v4.path("maximumDelegationEvidenceLength").asLong());
        require("DS04 all GrantBytes within 64 KiB",v4.path("allGrantBytesWithinLimit").asBoolean());
        JsonNode v5=d.path("vectors").get(4);require("DS05 exact 128-byte registryDomain",v5.path("registryDomainLength").asInt()==128&&HexFormat.of().parseHex(v5.path("registryDomainHex").asText()).length==128);
        JsonNode v6=d.path("vectors").get(5);byte[] eid=HexFormat.of().parseHex(v6.path("delegationEvidenceIdHex").asText());
        byte[] ctx=map(1,1,2,"https://as.example.test".getBytes(StandardCharsets.UTF_8),3,"client-016".getBytes(StandardCharsets.UTF_8),
                4,eid,5,"https://api.example.test".getBytes(StandardCharsets.UTF_8),6,"records.read".getBytes(StandardCharsets.UTF_8));
        require("DS06 context bytes",v6.path("contextBytesHex").asText().equals(hx(ctx)));
        require("DS06 contextHash",v6.path("contextHashHex").asText().equals(hx(mh(ctx))));
        require("DS06 token-exchange purpose","openidentity.oauth.token-exchange".equals(v6.path("purpose").asText()));
    }

    static void verifyInvalids(JsonNode d)throws Exception{
        JsonNode xs=d.path("invalidVectors");require("invalid vector count",xs.size()==22);
        String[] errors={"INVALID_DELEGATED_SUBJECT_VERSION","EMPTY_DELEGATION_PATH","DELEGATION_PATH_TOO_DEEP","GRANT_ID_MISMATCH",
                "INVALID_GRANT_EVIDENCE","PARENT_GRANT_MISMATCH","ROOT_GRANTOR_MISMATCH","ISSUER_DELEGATE_MISMATCH","INVALID_DELEGATION_EVIDENCE",
                "DELEGATION_NOT_CURRENTLY_USABLE","DELEGATION_NOT_CURRENTLY_USABLE","DELEGATION_NOT_CURRENTLY_USABLE",
                "DELEGATION_NOT_CURRENTLY_USABLE","DELEGATION_NOT_CURRENTLY_USABLE","DELEGATION_STATE_UNAVAILABLE",
                "ACTOR_ASSERTION_ID_MISMATCH","ACTOR_IDENTITY_MISMATCH","DELEGATION_CONTEXT_MISMATCH","ACTOR_ASSERTION_ID_MISMATCH",
                "DELEGATION_EVIDENCE_TOO_LARGE","INVALID_DELEGATION_EVIDENCE","INVALID_DELEGATION_EVIDENCE"};
        require("stable error table size",errors.length==xs.size());
        Map<String,JsonNode> m=new HashMap<>();
        for(int i=0;i<xs.size();i++){JsonNode v=xs.get(i);String id=String.format("DSI%02d",i+1);
            require(id+" stable error",id.equals(v.path("id").asText())&&errors[i].equals(v.path("expectedError").asText()));m.put(id,v);}
        require("DSI01 unsupported version",m.get("DSI01").path("submittedVersion").asInt()!=m.get("DSI01").path("supportedVersion").asInt());
        require("DSI02 empty path",m.get("DSI02").path("pathLength").asInt()<m.get("DSI02").path("minimumPathLength").asInt());
        require("DSI03 path too deep",m.get("DSI03").path("pathLength").asInt()>m.get("DSI03").path("maximumPathLength").asInt());
        require("DSI04 mutated bytes change GrantId",!m.get("DSI04").path("submittedGrantIdHex").asText().equals(m.get("DSI04").path("recomputedGrantIdHex").asText()));
        require("DSI05 unsupported GrantId multihash",m.get("DSI05").path("submittedMultihashCode").asInt()!=m.get("DSI05").path("expectedMultihashCode").asInt());
        require("DSI06 parent mismatch",!m.get("DSI06").path("previousGrantIdHex").asText().equals(m.get("DSI06").path("childParentGrantIdHex").asText()));
        require("DSI07 rootGrantor mismatch",!m.get("DSI07").path("rootGrantorHex").asText().equals(m.get("DSI07").path("childRootGrantorHex").asText()));
        require("DSI08 issuer/delegate mismatch",!m.get("DSI08").path("parentDelegateHex").asText().equals(m.get("DSI08").path("childIssuerHex").asText()));
        JsonNode i9=m.get("DSI09");require("DSI09 valid grants reordered",
                i9.path("submittedGrantIdsHex").get(0).asText().equals(i9.path("originalGrantIdsHex").get(1).asText())&&
                i9.path("submittedGrantIdsHex").get(1).asText().equals(i9.path("originalGrantIdsHex").get(0).asText()));
        for(String id:new String[]{"DSI10","DSI11","DSI12","DSI13","DSI14","DSI15"})
            require(id+" embedded evidence remains valid",m.get(id).path("embeddedEvidenceValid").asBoolean());
        require("DSI10 authoritative state resolved REVOKED",m.get("DSI10").path("authoritativeStateAvailable").asBoolean()&&"REVOKED".equals(m.get("DSI10").path("currentStatus").asText()));
        require("DSI11 ancestor relinquished",m.get("DSI11").path("authoritativeStateAvailable").asBoolean()&&m.get("DSI11").path("ancestorRelinquished").asBoolean());
        require("DSI12 delegation generation invalidated",m.get("DSI12").path("authoritativeStateAvailable").asBoolean()&&m.get("DSI12").path("boundDelegationGeneration").asLong()!=m.get("DSI12").path("currentDelegationGeneration").asLong());
        require("DSI13 root identity DEACTIVATED",m.get("DSI13").path("authoritativeStateAvailable").asBoolean()&&"DEACTIVATED".equals(m.get("DSI13").path("currentRootStatus").asText()));
        require("DSI14 ancestor expired",m.get("DSI14").path("authoritativeStateAvailable").asBoolean()&&m.get("DSI14").path("verificationTime").asLong()>=m.get("DSI14").path("ancestorExpiresAt").asLong());
        require("DSI15 authoritative state unavailable",!m.get("DSI15").path("authoritativeStateAvailable").asBoolean());
        JsonNode i16=m.get("DSI16");require("DSI16 different assertion id",!i16.path("tokenActorAssertionIdHex").asText().equals(i16.path("suppliedActorAssertionIdHex").asText()));
        require("DSI16 supplied assertion id reconstructs",i16.path("suppliedActorAssertionIdHex").asText().equals(hx(mh(HexFormat.of().parseHex(i16.path("suppliedAssertionBytesHex").asText())))));
        JsonNode i17=m.get("DSI17");require("DSI17 actor identity differs from terminal delegate",!i17.path("terminalDelegateHex").asText().equals(i17.path("authenticatedActorHex").asText()));
        JsonNode i18=m.get("DSI18");require("DSI18 context binds different evidence",!i18.path("expectedDelegationEvidenceIdHex").asText().equals(i18.path("boundDelegationEvidenceIdHex").asText()));
        require("DSI18 bound context hash reconstructs",i18.path("boundContextHashHex").asText().equals(hx(mh(HexFormat.of().parseHex(i18.path("boundDelegationEvidenceIdHex").asText())))));
        JsonNode i19=m.get("DSI19");require("DSI19 same actor but different assertion id",!i19.path("tokenActorAssertionIdHex").asText().equals(i19.path("substitutedActorAssertionIdHex").asText()));
        require("DSI19 substituted assertion id reconstructs",i19.path("substitutedActorAssertionIdHex").asText().equals(hx(mh(HexFormat.of().parseHex(i19.path("substitutedAssertionBytesHex").asText())))));
        JsonNode i20=m.get("DSI20");require("DSI20 evidence one over maximum",i20.path("delegationEvidenceLength").asLong()==i20.path("maximumDelegationEvidenceLength").asLong()+1);
        JsonNode i21=m.get("DSI21");require("DSI21 independent path B grant itself valid",i21.path("individualPathBGrantIdValid").asBoolean());
        require("DSI21 roots differ",!i21.path("pathARootGrantorHex").asText().equals(i21.path("pathBRootGrantorHex").asText()));
        require("DSI21 splice lacks parent linkage",!i21.path("splicedNextParentGrantIdPresent").asBoolean());
        JsonNode i22=m.get("DSI22");Set<String> ids22=new HashSet<>();boolean dup22=false;for(JsonNode x:i22.path("submittedGrantIdsHex"))if(!ids22.add(x.asText()))dup22=true;
        require("DSI22 duplicate/cycle GrantId",dup22);
    }

    public static void main(String[] args)throws Exception{
        Path p=findVectorFile();System.out.println("Using vectors: "+p);
        JsonNode d=JSON.readTree(Files.readString(p));
        require("suite specification","OpenIdentity OI-016 Delegated Subject Token v1".equals(d.path("specification").asText()));
        require("draft status","DRAFT-NON-NORMATIVE".equals(d.path("status").asText()));
        require("vector IDs DS01-DS06",d.path("vectors").size()==6&&"DS01".equals(d.path("vectors").get(0).path("id").asText())&&"DS06".equals(d.path("vectors").get(5).path("id").asText()));
        verifyDS01(d.path("vectors").get(0));verifyDS02(d.path("vectors").get(1));verifyDS03to06(d);verifyInvalids(d);
        System.out.println("\n============================================");
        System.out.println("OI-016 DELEGATED SUBJECT v1 JAVA DS01-DS06 + DSI01-DSI22 VERIFIED");
        System.out.println("============================================");
    }
}
