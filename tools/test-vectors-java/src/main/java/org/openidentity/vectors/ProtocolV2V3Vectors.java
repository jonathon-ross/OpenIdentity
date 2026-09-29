package org.openidentity.vectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Independent Java verification for draft Protocol v2 / IdentityState v3.
 *
 * This class deliberately does not modify or call the frozen v0.1 vector
 * generator. It reconstructs v3 canonical bytes using the low-level
 * deterministic CBOR and crypto primitives and compares them with the
 * Python-generated draft bundle.
 */
public final class ProtocolV2V3Vectors {
    private static final byte[] IDENTITY = range(0, 32);

    private ProtocolV2V3Vectors() {}

    public static void main(String[] args) throws Exception {
        Path root = Path.of("..", "..").toAbsolutePath().normalize();
        JsonNode doc = new ObjectMapper().readTree(
                root.resolve("test-vectors/generated/protocol-v2-identity-state-v3.json").toFile());
        require("suite specification",
                "OpenIdentity Protocol v2 / IdentityState v3".equals(doc.path("specification").asText()));
        require("positive vector count", doc.path("vectors").size() == 24);
        require("invalid vector count", doc.path("invalidVectors").size() == 37);

        verifyV301(find(doc, "V301"));
        verifyV302(find(doc, "V302"));
        verifyV303(find(doc, "V303"));
        verifyV304(find(doc, "V304"));
        verifyV305(find(doc, "V305")); verifyV306(find(doc, "V306"));
        verifyV307(find(doc, "V307")); verifyV308(find(doc, "V308"));
        verifyV309(find(doc, "V309")); verifyV310(find(doc, "V310"));
        verifyV311(find(doc, "V311")); verifyV312(find(doc, "V312")); verifyV313(find(doc, "V313"));
        verifyV314(find(doc, "V314")); verifyV315(find(doc, "V315")); verifyV316(find(doc, "V316"));
        verifyV317(find(doc, "V317")); verifyV318(find(doc, "V318"));
        verifyV319(find(doc, "V319")); verifyV320(find(doc, "V320"));
        verifyV321(find(doc, "V321")); verifyV322(find(doc, "V322"));
        verifyV323(find(doc, "V323")); verifyV324(find(doc, "V324"));
        verifyInvalidSuite(doc);

        System.out.println();
        System.out.println("================================================");
        System.out.println("PROTOCOL V2 / IDENTITYSTATE V3 JAVA V301-V324 + VI301-VI337 VERIFIED");
        System.out.println("================================================");
    }

    private static void verifyV301(JsonNode v) throws Exception {
        Key c = key("OpenIdentity protocol-v2 v3 V301 controller Ed25519 seed", 0);
        byte[] cp = policy(c.method);
        byte[] op = operation(1, 1, null, map(entry(1, cp)));
        byte[] signing = signing("OpenIdentity Operation", op, null);
        byte[] sig = c.ed.sign(signing);
        require("V301 OperationBytes", eq(v, "operationBytesHex", op));
        require("V301 signing input", eq(v, "operationSigningBytesHex", signing));
        require("V301 signature", eq(v, "controllerSignatureHex", sig));
        byte[] state = state(3, 1, 1, cp, null, null,
                authority(0, null), authority(0, null));
        require("V301 StateBytes", eq(v, "stateBytesHex", state));
        require("V301 StateHash", eq(v, "stateHashHex", StateHash.sha256Multihash(state)));
    }

    private static void verifyV302(JsonNode v) throws Exception {
        Key c = key("OpenIdentity protocol-v2 v3 V302 controller Ed25519 seed", 0);
        Key a = key("OpenIdentity protocol-v2 v3 V302 authentication Ed25519 seed", 16);
        byte[] cp=policy(c.method), ap=policy(a.method);
        byte[] op=operation(1,1,null,map(entry(1,cp),entry(4,ap)));
        byte[] cs=signing("OpenIdentity Operation",op,null);
        byte[] as=signing("OpenIdentity Authentication Proof",op,a.id);
        require("V302 OperationBytes",eq(v,"operationBytesHex",op));
        require("V302 controller signature",eq(v,"controllerSignatureHex",c.ed.sign(cs)));
        require("V302 authentication signature",eq(v,"authenticationProofSignatureHex",a.ed.sign(as)));
        byte[] state=state(3,1,1,cp,null,null,authority(0,ap),authority(0,null));
        require("V302 StateBytes",eq(v,"stateBytesHex",state));
        require("V302 StateHash",eq(v,"stateHashHex",StateHash.sha256Multihash(state)));
    }

    private static void verifyV303(JsonNode v) throws Exception {
        Key c=key("OpenIdentity protocol-v2 v3 V303 controller Ed25519 seed",0);
        Key a=key("OpenIdentity protocol-v2 v3 V303 authentication Ed25519 seed",16);
        Key s=key("OpenIdentity protocol-v2 v3 V303 assertion Ed25519 seed",32);
        Key d=key("OpenIdentity protocol-v2 v3 V303 delegation Ed25519 seed",48);
        byte[] cp=policy(c.method),ap=policy(a.method),sp=policy(s.method),dp=policy(d.method);
        byte[] op=operation(1,1,null,map(entry(1,cp),entry(3,sp),entry(4,ap),entry(5,dp)));
        require("V303 OperationBytes",eq(v,"operationBytesHex",op));
        require("V303 controller signature",eq(v,"controllerSignatureHex",c.ed.sign(signing("OpenIdentity Operation",op,null))));
        require("V303 authentication signature",eq(v,"authenticationProofSignatureHex",a.ed.sign(signing("OpenIdentity Authentication Proof",op,a.id))));
        require("V303 assertion signature",eq(v,"assertionProofSignatureHex",s.ed.sign(signing("OpenIdentity Assertion Proof",op,s.id))));
        require("V303 delegation signature",eq(v,"delegationProofSignatureHex",d.ed.sign(signing("OpenIdentity Delegation Proof",op,d.id))));
        byte[] state=state(3,1,1,cp,null,sp,authority(0,ap),authority(0,dp));
        require("V303 StateBytes",eq(v,"stateBytesHex",state));
        require("V303 StateHash",eq(v,"stateHashHex",StateHash.sha256Multihash(state)));
    }

    private static void verifyV304(JsonNode v) throws Exception {
        Key c=key("OpenIdentity protocol-v2 v3 V304 controller Ed25519 seed",0);
        Key a=key("OpenIdentity protocol-v2 v3 V304 authentication Ed25519 seed",16);
        byte[] cp=policy(c.method),ap=policy(a.method);
        byte[] previous=state(2,1,1,cp,null,null,null,null);
        byte[] ph=StateHash.sha256Multihash(previous);
        byte[] op=operation(6,2,ph,map(entry(1,ap)));
        require("V304 previous StateBytes",eq(v,"previousStateBytesHex",previous));
        require("V304 previous StateHash",eq(v,"previousStateHashHex",ph));
        require("V304 OperationBytes",eq(v,"operationBytesHex",op));
        require("V304 controller signature",eq(v,"controllerSignatureHex",c.ed.sign(signing("OpenIdentity Operation",op,null))));
        require("V304 authentication signature",eq(v,"authenticationProofSignatureHex",a.ed.sign(signing("OpenIdentity Authentication Proof",op,a.id))));
        byte[] result=state(3,2,1,cp,null,null,authority(0,ap),authority(0,null));
        require("V304 StateBytes",eq(v,"stateBytesHex",result));
        require("V304 StateHash",eq(v,"stateHashHex",StateHash.sha256Multihash(result)));
    }


    private static void verifyAuthRotation(JsonNode v,String id,long disposition,long before,long after) throws Exception {
        Key c=key("OpenIdentity protocol-v2 v3 "+id+" controller Ed25519 seed",0);
        Key a=key("OpenIdentity protocol-v2 v3 "+id+" authentication A Ed25519 seed",16);
        Key b=key("OpenIdentity protocol-v2 v3 "+id+" authentication B Ed25519 seed",32);
        byte[] cp=policy(c.method),ap=policy(a.method),bp=policy(b.method);
        byte[] prev=state(3,1,1,cp,null,null,authority(before,ap),authority(0,null));
        byte[] ph=StateHash.sha256Multihash(prev);
        byte[] op=operation(6,2,ph,map(entry(1,bp),uintEntry(2,disposition)));
        require(id+" previous StateBytes",eq(v,"previousStateBytesHex",prev));
        require(id+" OperationBytes",eq(v,"operationBytesHex",op));
        require(id+" controller signature",eq(v,"controllerSignatureHex",c.ed.sign(signing("OpenIdentity Operation",op,null))));
        require(id+" authentication signature",eq(v,"authenticationProofSignatureHex",b.ed.sign(signing("OpenIdentity Authentication Proof",op,b.id))));
        byte[] result=state(3,2,1,cp,null,null,authority(after,bp),authority(0,null));
        require(id+" StateBytes",eq(v,"stateBytesHex",result));
        require(id+" StateHash",eq(v,"stateHashHex",StateHash.sha256Multihash(result)));
    }

    private static void verifyV305(JsonNode v)throws Exception{verifyAuthRotation(v,"V305",2,0,0);}
    private static void verifyV306(JsonNode v)throws Exception{verifyAuthRotation(v,"V306",1,0,1);}

    private static void verifyV307(JsonNode v)throws Exception{
        Key c=key("OpenIdentity protocol-v2 v3 V307 controller Ed25519 seed",0);
        Key a=key("OpenIdentity protocol-v2 v3 V307 authentication Ed25519 seed",16);
        byte[] cp=policy(c.method),ap=policy(a.method);
        byte[] prev=state(3,1,1,cp,null,null,authority(4,ap),authority(0,null));
        byte[] op=operation(6,2,StateHash.sha256Multihash(prev),map(nullEntry(1)));
        byte[] result=state(3,2,1,cp,null,null,authority(5,null),authority(0,null));
        require("V307 OperationBytes",eq(v,"operationBytesHex",op));
        require("V307 StateBytes",eq(v,"stateBytesHex",result));
        require("V307 StateHash",eq(v,"stateHashHex",StateHash.sha256Multihash(result)));
    }

    private static void verifyV308(JsonNode v)throws Exception{
        Key c=key("OpenIdentity protocol-v2 v3 V308 controller Ed25519 seed",0);
        Key a=key("OpenIdentity protocol-v2 v3 V308 authentication Ed25519 seed",16);
        byte[] cp=policy(c.method),ap=policy(a.method);
        byte[] prev=state(3,7,1,cp,null,null,authority(9,ap),authority(0,null));
        byte[] op=operation(8,8,StateHash.sha256Multihash(prev),map());
        byte[] result=state(3,8,1,cp,null,null,authority(10,ap),authority(0,null));
        require("V308 OperationBytes",eq(v,"operationBytesHex",op));
        require("V308 StateBytes",eq(v,"stateBytesHex",result));
        require("V308 StateHash",eq(v,"stateHashHex",StateHash.sha256Multihash(result)));
    }

    private static void verifyDelegation(JsonNode v,String id,String mode,long disposition,long before,long after)throws Exception{
        Key c=key("OpenIdentity protocol-v2 v3 "+id+" controller Ed25519 seed",0);
        Key a=key("OpenIdentity protocol-v2 v3 "+id+" delegation A Ed25519 seed",16);
        Key b=key("OpenIdentity protocol-v2 v3 "+id+" delegation B Ed25519 seed",32);
        byte[] cp=policy(c.method),ap=policy(a.method),bp=policy(b.method);
        byte[] prev=state(3,1,1,cp,null,null,authority(0,null),authority(before,"install".equals(mode)?null:ap));
        byte[] ph=StateHash.sha256Multihash(prev);
        byte[] payload;
        byte[] resultPolicy;
        long type;
        if("reset".equals(mode)){type=9;payload=map();resultPolicy=ap;}
        else {
            type=7;
            resultPolicy="remove".equals(mode)?null:("install".equals(mode)?ap:bp);
            payload=disposition<0?map(resultPolicy==null?nullEntry(1):entry(1,resultPolicy))
                    :map(resultPolicy==null?nullEntry(1):entry(1,resultPolicy),uintEntry(2,disposition));
        }
        byte[] op=operation(type,2,ph,payload);
        require(id+" OperationBytes",eq(v,"operationBytesHex",op));
        if(resultPolicy!=null && !"reset".equals(mode)){
            Key proof="rotate".equals(mode)?b:a;
            require(id+" delegation signature",eq(v,"delegationProofSignatureHex",
                    proof.ed.sign(signing("OpenIdentity Delegation Proof",op,proof.id))));
        }
        byte[] result=state(3,2,1,cp,null,null,authority(0,null),authority(after,resultPolicy));
        require(id+" StateBytes",eq(v,"stateBytesHex",result));
        require(id+" StateHash",eq(v,"stateHashHex",StateHash.sha256Multihash(result)));
    }

    private static void verifyV309(JsonNode v)throws Exception{verifyDelegation(v,"V309","install",-1,0,0);}
    private static void verifyV310(JsonNode v)throws Exception{verifyDelegation(v,"V310","rotate",2,4,4);}
    private static void verifyV311(JsonNode v)throws Exception{verifyDelegation(v,"V311","rotate",1,4,5);}
    private static void verifyV312(JsonNode v)throws Exception{verifyDelegation(v,"V312","remove",-1,4,5);}
    private static void verifyV313(JsonNode v)throws Exception{verifyDelegation(v,"V313","reset",-1,9,10);}

    private static byte[] recoveryPolicy(byte[] method){
        var c=new DeterministicCborWriter();c.writeMapHeader(3);
        c.writeUnsigned(1);c.writeUnsigned(1);c.writeUnsigned(2);c.writeUnsigned(1);
        c.writeUnsigned(3);c.writeArrayHeader(1);c.writeEncoded(method);return c.toByteArray();
    }

    private static void verifyRecovery(JsonNode v,String id,int disposition,int sourceVersion,int sourceStatus,boolean replace)throws Exception{
        Key oldc=key("OpenIdentity protocol-v2 v3 "+id+" old controller Ed25519 seed",0);
        Key newc=key("OpenIdentity protocol-v2 v3 "+id+" new controller Ed25519 seed",16);
        Key r=key("OpenIdentity protocol-v2 v3 "+id+" recovery Ed25519 seed",32);
        Key olda=key("OpenIdentity protocol-v2 v3 "+id+" assertion A Ed25519 seed",48);
        Key newa=key("OpenIdentity protocol-v2 v3 "+id+" assertion B Ed25519 seed",64);
        Key auth=key("OpenIdentity protocol-v2 v3 "+id+" authentication Ed25519 seed",80);
        Key del=key("OpenIdentity protocol-v2 v3 "+id+" delegation Ed25519 seed",96);
        byte[] oldcp=policy(oldc.method),newcp=policy(newc.method),oldap=policy(olda.method),newap=policy(newa.method);
        byte[] rp=recoveryPolicy(r.method),rc=StateHash.sha256Multihash(rp),newrc=StateHash.sha256Multihash(recoveryPolicy(newc.method));
        byte[] prev=state(sourceVersion,5,sourceStatus,oldcp,rc,oldap,
                sourceVersion==3?authority(3,policy(auth.method)):null,
                sourceVersion==3?authority(7,policy(del.method)):null);
        Entry[] pe=replace?new Entry[]{entry(1,newcp),entry(2,rp),bytesEntry(3,newrc),uintEntry(4,disposition),entry(5,newap)}
                :new Entry[]{entry(1,newcp),entry(2,rp),bytesEntry(3,newrc),uintEntry(4,disposition)};
        byte[] op=operation(3,6,StateHash.sha256Multihash(prev),map(pe));
        require(id+" OperationBytes",eq(v,"operationBytesHex",op));
        require(id+" controller PoP",eq(v,"controllerProofSignatureHex",newc.ed.sign(signing("OpenIdentity Controller Proof",op,newc.id))));
        require(id+" recovery signature",eq(v,"recoverySignatureHex",r.ed.sign(signing("OpenIdentity Recovery",op,r.id))));
        if(replace)require(id+" assertion PoP",eq(v,"assertionProofSignatureHex",newa.ed.sign(signing("OpenIdentity Assertion Proof",op,newa.id))));
        byte[] assertion=disposition==1?oldap:(disposition==3?newap:null);
        byte[] result=state(3,6,1,newcp,newrc,assertion,authority(sourceVersion==2?1:4,null),authority(sourceVersion==2?1:8,null));
        require(id+" StateBytes",eq(v,"stateBytesHex",result));
        require(id+" StateHash",eq(v,"stateHashHex",StateHash.sha256Multihash(result)));
    }

    private static void verifyV314(JsonNode v)throws Exception{verifyRecovery(v,"V314",1,3,1,false);}
    private static void verifyV315(JsonNode v)throws Exception{verifyRecovery(v,"V315",2,3,1,false);}
    private static void verifyV316(JsonNode v)throws Exception{verifyRecovery(v,"V316",3,3,1,true);}
    private static void verifyV317(JsonNode v)throws Exception{verifyRecovery(v,"V317",1,3,2,false);}
    private static void verifyV318(JsonNode v)throws Exception{verifyRecovery(v,"V318",1,2,1,false);}
    private static void verifyV319(JsonNode v)throws Exception{verifyDelegation(v,"V319","rotate",2,42,42);}
    private static void verifyV320(JsonNode v)throws Exception{verifyDelegation(v,"V320","reset",-1,42,43);}



    private static void verifyV321(JsonNode v)throws Exception{
        Key c=key("OpenIdentity protocol-v2 v3 V321 controller Ed25519 seed",0);
        Key d=key("OpenIdentity protocol-v2 v3 V321 delegation Ed25519 seed",16);
        byte[] cp=policy(c.method),dp=policy(d.method);
        byte[] prev=state(2,1,1,cp,null,null,null,null);
        byte[] op=operation(7,2,StateHash.sha256Multihash(prev),map(entry(1,dp)));
        require("V321 OperationBytes",eq(v,"operationBytesHex",op));
        require("V321 controller signature",eq(v,"controllerSignatureHex",c.ed.sign(signing("OpenIdentity Operation",op,null))));
        require("V321 delegation PoP",eq(v,"delegationProofSignatureHex",d.ed.sign(signing("OpenIdentity Delegation Proof",op,d.id))));
        byte[] result=state(3,2,1,cp,null,null,authority(0,null),authority(0,dp));
        require("V321 StateBytes",eq(v,"stateBytesHex",result));
        require("V321 StateHash",eq(v,"stateHashHex",StateHash.sha256Multihash(result)));
    }

    private static void verifyV322(JsonNode v)throws Exception{
        Key oldc=key("OpenIdentity protocol-v2 v3 V322 old controller Ed25519 seed",0);
        Key newc=key("OpenIdentity protocol-v2 v3 V322 new controller Ed25519 seed",16);
        byte[] oldp=policy(oldc.method),newp=policy(newc.method);
        byte[] prev=state(2,4,1,oldp,null,null,null,null);
        byte[] op=operation(2,5,StateHash.sha256Multihash(prev),map(entry(1,newp)));
        require("V322 OperationBytes",eq(v,"operationBytesHex",op));
        require("V322 controller signature",eq(v,"controllerSignatureHex",oldc.ed.sign(signing("OpenIdentity Operation",op,null))));
        require("V322 controller PoP",eq(v,"controllerProofSignatureHex",newc.ed.sign(signing("OpenIdentity Controller Proof",op,newc.id))));
        byte[] result=state(3,5,1,newp,null,null,authority(0,null),authority(0,null));
        require("V322 StateBytes",eq(v,"stateBytesHex",result));
        require("V322 StateHash",eq(v,"stateHashHex",StateHash.sha256Multihash(result)));
    }


    private static void verifyRich(JsonNode v,String id,boolean deactivate)throws Exception{
        Key c=key("OpenIdentity protocol-v2 v3 "+id+" controller Ed25519 seed",0);
        Key r=key("OpenIdentity protocol-v2 v3 "+id+" recovery Ed25519 seed",16);
        Key a=key("OpenIdentity protocol-v2 v3 "+id+" assertion Ed25519 seed",32);
        Key aa=key("OpenIdentity protocol-v2 v3 "+id+" authentication A Ed25519 seed",48);
        Key ab=key("OpenIdentity protocol-v2 v3 "+id+" authentication B Ed25519 seed",64);
        Key d=key("OpenIdentity protocol-v2 v3 "+id+" delegation Ed25519 seed",80);
        byte[] cp=policy(c.method),rc=StateHash.sha256Multihash(recoveryPolicy(r.method)),sp=policy(a.method),
                ap=policy(aa.method),bp=policy(ab.method),dp=policy(d.method);
        byte[] prev=state(3,12,1,cp,rc,sp,authority(7,ap),authority(11,dp));
        byte[] op=deactivate?operation(4,13,StateHash.sha256Multihash(prev),map())
                :operation(6,13,StateHash.sha256Multihash(prev),map(entry(1,bp),uintEntry(2,1)));
        require(id+" OperationBytes",eq(v,"operationBytesHex",op));
        require(id+" controller signature",eq(v,"controllerSignatureHex",c.ed.sign(signing("OpenIdentity Operation",op,null))));
        if(!deactivate)require(id+" authentication PoP",eq(v,"authenticationProofSignatureHex",
                ab.ed.sign(signing("OpenIdentity Authentication Proof",op,ab.id))));
        byte[] result=deactivate?state(3,13,2,cp,rc,sp,authority(7,ap),authority(11,dp))
                :state(3,13,1,cp,rc,sp,authority(8,bp),authority(11,dp));
        require(id+" StateBytes",eq(v,"stateBytesHex",result));
        require(id+" StateHash",eq(v,"stateHashHex",StateHash.sha256Multihash(result)));
    }
    private static void verifyV323(JsonNode v)throws Exception{verifyRich(v,"V323",false);}
    private static void verifyV324(JsonNode v)throws Exception{verifyRich(v,"V324",true);}

    private static JsonNode invalid(JsonNode doc,String id){
        for(JsonNode v:doc.path("invalidVectors"))if(id.equals(v.path("id").asText()))return v;
        throw new IllegalStateException("Missing invalid vector "+id);
    }

    private static void verifyInvalidSuite(JsonNode doc)throws Exception{
        System.out.println();
        System.out.println("Java VI301-VI332 Rejection Verification");
        System.out.println("------------------------------------------------");
        for(int i=301;i<=337;i++){
            String id="VI"+i; JsonNode v=invalid(doc,id);
            require(id+" expected REJECT","REJECT".equals(v.path("expected").asText()));
            require(id+" expected error present",!v.path("expectedError").asText().isBlank());
        }

        // Cryptographic wrong-domain attacks: valid in source domain, invalid in required domain.
        for(String id:new String[]{"VI302","VI306","VI325","VI326","VI327"}){
            JsonNode v=invalid(doc,id);
            byte[] pub=Hex.decode(v.path("publicKeyHex").asText());
            byte[] sig=Hex.decode(v.path("signatureHex").asText());
            String sourceField=v.has("wrongSigningBytesHex")?"wrongSigningBytesHex":"sourceSigningBytesHex";
            byte[] source=Hex.decode(v.path(sourceField).asText());
            byte[] required=Hex.decode(v.path("requiredSigningBytesHex").asText());
            require(id+" source-domain signature verifies",verifyPublic(pub,source,sig));
            require(id+" required-domain signature rejects",!verifyPublic(pub,required,sig));
        }

        require("VI303 duplicate Authentication proofs",
                invalid(doc,"VI303").path("proofsHex").get(0).asText().equals(invalid(doc,"VI303").path("proofsHex").get(1).asText()));
        require("VI307 duplicate Delegation proofs",
                invalid(doc,"VI307").path("proofsHex").get(0).asText().equals(invalid(doc,"VI307").path("proofsHex").get(1).asText()));
        require("VI304 unauthorized method differs",!invalid(doc,"VI304").path("authorizedMethodIdHex").asText()
                .equals(invalid(doc,"VI304").path("unauthorizedMethodIdHex").asText()));
        require("VI308 unauthorized method differs",!invalid(doc,"VI308").path("authorizedMethodIdHex").asText()
                .equals(invalid(doc,"VI308").path("unauthorizedMethodIdHex").asText()));

        // Byte-complete transition/state-machine attacks.
        for(String id:new String[]{"VI309","VI310","VI311","VI312","VI313","VI314","VI315",
                "VI316","VI317","VI318","VI319","VI320","VI321","VI322","VI323","VI324",
                "VI329","VI330","VI331","VI332"}){
            JsonNode v=invalid(doc,id);
            require(id+" OperationBytes present",v.has("operationBytesHex") && Hex.decode(v.path("operationBytesHex").asText()).length>0);
        }
        require("VI312 exact A->A policy bytes",
                invalid(doc,"VI312").path("currentPolicyBytesHex").asText().equals(invalid(doc,"VI312").path("proposedPolicyBytesHex").asText()));
        require("VI313 generation jump",invalid(doc,"VI313").path("proposedGeneration").asLong()
                > invalid(doc,"VI313").path("currentGeneration").asLong()+1);
        require("VI314 generation decrease",invalid(doc,"VI314").path("proposedGeneration").asLong()
                < invalid(doc,"VI314").path("currentGeneration").asLong());
        require("VI315 uint64 overflow boundary",
                "18446744073709551616".equals(invalid(doc,"VI315").path("requiredNextGeneration").asText()));
        require("VI321 missing Assertion PoP field 6",invalid(doc,"VI321").path("missingProofField").asInt()==6);
        require("VI322 downgrade 3->2",invalid(doc,"VI322").path("sourceStateVersion").asInt()==3
                && invalid(doc,"VI322").path("proposedStateVersion").asInt()==2);
        require("VI323 PV1 on v3",invalid(doc,"VI323").path("sourceStateVersion").asInt()==3
                && invalid(doc,"VI323").path("operationProtocolVersion").asInt()==1);
        require("VI324 proof map where array required","map".equals(invalid(doc,"VI324").path("encodedMajorType").asText())
                && "array".equals(invalid(doc,"VI324").path("requiredMajorType").asText()));

        JsonNode d=invalid(doc,"VI328");
        require("VI328 distinct method IDs",!d.path("methodId1Hex").asText().equals(d.path("methodId2Hex").asText()));
        require("VI328 identical effective COSE_Key",d.path("coseKey1Hex").asText().equals(d.path("coseKey2Hex").asText()));

        require("VI329 forbidden CREATE field 3",invalid(doc,"VI329").path("forbiddenProofField").asInt()==3
                && invalid(doc,"VI329").has("signedOperationBytesHex"));
        require("VI330 forbidden RESET field 5",invalid(doc,"VI330").path("forbiddenProofField").asInt()==5
                && invalid(doc,"VI330").has("signedOperationBytesHex"));
        require("VI331 forbidden RECOVER field 2",invalid(doc,"VI331").path("forbiddenProofField").asInt()==2
                && invalid(doc,"VI331").has("signedOperationBytesHex"));
        require("VI333 RESET_AUTHENTICATION requires v3 predecessor",
                invalid(doc,"VI333").path("predecessorStateVersion").asInt()==2 && invalid(doc,"VI333").path("operationType").asInt()==8);
        require("VI334 RESET_DELEGATIONS requires v3 predecessor",
                invalid(doc,"VI334").path("predecessorStateVersion").asInt()==2 && invalid(doc,"VI334").path("operationType").asInt()==9);
        require("VI335 ROTATE_CONTROLLER rejected while deactivated",
                "DEACTIVATED".equals(invalid(doc,"VI335").path("predecessorStatus").asText())
                        && invalid(doc,"VI335").path("operationType").asInt()==2);
        require("VI336 SET_AUTHENTICATION_POLICY rejected while deactivated",
                "DEACTIVATED".equals(invalid(doc,"VI336").path("predecessorStatus").asText())
                        && invalid(doc,"VI336").path("operationType").asInt()==6);
        require("VI337 uint64 sequence terminal condition",
                "18446744073709551615".equals(invalid(doc,"VI337").path("predecessorSequence").asText())
                        && "18446744073709551616".equals(invalid(doc,"VI337").path("requiredNextSequence").asText()));
        require("VI332 PRESERVE plus replacement",invalid(doc,"VI332").path("disposition").asInt()==1
                && invalid(doc,"VI332").path("replacementAssertionPolicyPresent").asBoolean());

        System.out.println("VI301-VI337: PASS");
    }

    private static boolean verifyPublic(byte[] publicKey,byte[] message,byte[] signature){
        var p=new org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(publicKey);
        var verifier=new org.bouncycastle.crypto.signers.Ed25519Signer();
        verifier.init(false,p);verifier.update(message,0,message.length);
        return verifier.verifySignature(signature);
    }

    private record Key(Ed25519Support ed, byte[] id, byte[] method) {}
    private record Entry(long label, byte[] encoded) {}
    private static Entry uintEntry(long label,long value){var c=new DeterministicCborWriter();c.writeUnsigned(value);return new Entry(label,c.toByteArray());}
    private static Entry nullEntry(long label){var c=new DeterministicCborWriter();c.writeNull();return new Entry(label,c.toByteArray());}
    private static Entry bytesEntry(long label,byte[] value){var c=new DeterministicCborWriter();c.writeByteString(value);return new Entry(label,c.toByteArray());}

    private static Key key(String label,int start) throws Exception {
        byte[] seed=MessageDigest.getInstance("SHA-256").digest(label.getBytes(StandardCharsets.US_ASCII));
        Ed25519Support ed=new Ed25519Support(seed);
        byte[] id=range(start,16);
        byte[] method=OpenIdentityCbor.verificationMethod(id,OpenIdentityCbor.ed25519CoseKey(ed.publicKey())).encoded();
        return new Key(ed,id,method);
    }

    private static byte[] policy(byte[] method) {
        var c=new DeterministicCborWriter();
        c.writeMapHeader(2); c.writeUnsigned(1); c.writeUnsigned(1);
        c.writeUnsigned(2); c.writeArrayHeader(1); c.writeEncoded(method);
        return c.toByteArray();
    }

    private static byte[] authority(long generation,byte[] policy) {
        var c=new DeterministicCborWriter();
        c.writeMapHeader(policy==null?1:2); c.writeUnsigned(1); c.writeUnsigned(generation);
        if(policy!=null){c.writeUnsigned(2);c.writeEncoded(policy);}
        return c.toByteArray();
    }

    private static byte[] operation(long type,long seq,byte[] prev,byte[] payload) {
        var c=new DeterministicCborWriter(); c.writeMapHeader(6);
        c.writeUnsigned(1);c.writeUnsigned(2); c.writeUnsigned(2);c.writeUnsigned(type);
        c.writeUnsigned(3);c.writeByteString(IDENTITY); c.writeUnsigned(4);c.writeUnsigned(seq);
        c.writeUnsigned(5); if(prev==null)c.writeNull(); else c.writeByteString(prev);
        c.writeUnsigned(6);c.writeEncoded(payload); return c.toByteArray();
    }

    private static byte[] state(int version,long seq,int status,byte[] cp,byte[] recovery,byte[] assertion,
                                byte[] auth,byte[] delegation) {
        int n=5+(recovery==null?0:1)+(assertion==null?0:1)+(auth==null?0:1)+(delegation==null?0:1);
        var c=new DeterministicCborWriter();c.writeMapHeader(n);
        c.writeUnsigned(1);c.writeUnsigned(version);c.writeUnsigned(2);c.writeByteString(IDENTITY);
        c.writeUnsigned(3);c.writeUnsigned(seq);c.writeUnsigned(4);c.writeUnsigned(status);
        c.writeUnsigned(5);c.writeEncoded(cp);
        if(recovery!=null){c.writeUnsigned(6);c.writeByteString(recovery);}
        if(assertion!=null){c.writeUnsigned(7);c.writeEncoded(assertion);}
        if(auth!=null){c.writeUnsigned(8);c.writeEncoded(auth);}
        if(delegation!=null){c.writeUnsigned(9);c.writeEncoded(delegation);}
        return c.toByteArray();
    }

    private static byte[] signing(String domain,byte[] op,byte[] methodId) {
        var c=new DeterministicCborWriter();c.writeArrayHeader(methodId==null?3:4);
        c.writeTextString(domain);c.writeUnsigned(1);c.writeByteString(op);
        if(methodId!=null)c.writeByteString(methodId);return c.toByteArray();
    }

    private static Entry entry(long label,byte[] value){return new Entry(label,value);}
    private static byte[] map(Entry... entries){
        var c=new DeterministicCborWriter();c.writeMapHeader(entries.length);
        for(Entry e:entries){c.writeUnsigned(e.label);c.writeEncoded(e.encoded);}return c.toByteArray();
    }
    private static byte[] range(int start,int count){byte[] b=new byte[count];for(int i=0;i<count;i++)b[i]=(byte)(start+i);return b;}
    private static JsonNode find(JsonNode doc,String id){
        for(JsonNode v:doc.path("vectors"))if(id.equals(v.path("id").asText()))return v;
        throw new IllegalStateException("Missing "+id);
    }
    private static boolean eq(JsonNode v,String field,byte[] actual){return Arrays.equals(Hex.decode(v.path(field).asText()),actual);}
    private static void require(String name,boolean ok){if(!ok)throw new IllegalStateException(name+" failed");System.out.println("  "+name+": PASS");}
}
