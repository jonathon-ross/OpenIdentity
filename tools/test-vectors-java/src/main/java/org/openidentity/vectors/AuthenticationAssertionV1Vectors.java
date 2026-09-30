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



    static void verifyAA04(JsonNode v)throws Exception{
        byte[] audience=new byte[]{0,(byte)0xff,(byte)0x80,0x41,0x2f,0,(byte)0xfe};
        require("AA04 audience exact opaque bytes",v.path("audienceHex").asText().equals(hx(audience)));
        require("AA04 audience contains non-UTF8 octets",(audience[1]&255)==255&&(audience[2]&255)==128);
    }

    static void verifyAA05(JsonNode v)throws Exception{
        byte[] identity=seq(64,32),oldmid=seq(0,16),newmid=seq(16,16);long generation=42;
        Key oldk=new Key("OpenIdentity OI-015 AA05 old authentication seed"),newk=new Key("OpenIdentity OI-015 AA05 new authentication seed");
        byte[] oldap=singlePolicy(oldmid,oldk.pub()),newap=singlePolicy(newmid,newk.pub());
        byte[] ctrlid=seq(32,16);Key ctrl=new Key("OpenIdentity OI-015 AA05 controller seed");byte[] cp=singlePolicy(ctrlid,ctrl.pub());
        byte[] before=map(1,3,2,identity,3,80,4,1,5,E(cp),8,E(map(1,generation,2,E(oldap))),9,E(map(1,0)));
        byte[] after=map(1,3,2,identity,3,81,4,1,5,E(cp),8,E(map(1,generation,2,E(newap))),9,E(map(1,0)));
        require("AA05 generation preserved",v.path("generationBefore").asLong()==generation&&v.path("generationAfter").asLong()==generation);
        require("AA05 pre-rotation StateHash",v.path("preRotationStateHashHex").asText().equals(hx(mh(before))));
        require("AA05 current StateHash",v.path("stateHashHex").asText().equals(hx(mh(after))));
        require("AA05 rotation changes StateHash",!Arrays.equals(mh(before),mh(after)));
        require("AA05 current new policy signature verifies",newk.verify(hex(v.path("signingBytesHex").asText()),hex(v.path("signatureHex").asText())));
    }

    static void verifyAA06(JsonNode v)throws Exception{
        byte[] ctx=map(1,"https://as.example.test".getBytes(StandardCharsets.UTF_8),2,"client-123".getBytes(StandardCharsets.UTF_8),
                3,"https://api.example.test".getBytes(StandardCharsets.UTF_8),4,"urn:ietf:params:oauth:grant-type:token-exchange".getBytes(StandardCharsets.UTF_8));
        require("AA06 deterministic OAuth context bytes",v.path("contextBytesHex").asText().equals(hx(ctx)));
        require("AA06 contextHash",v.path("contextHashHex").asText().equals(hx(mh(ctx))));
        require("AA06 OAuth purpose","openidentity.oauth.token-exchange".equals(v.path("purpose").asText()));
    }

    static void verifyInvalids(JsonNode d)throws Exception{
        JsonNode xs=d.path("invalidVectors");require("invalid vector count",xs.size()==31);
        String[] errors={"INVALID_STATE_HASH","INVALID_AUTHENTICATION_GENERATION","IDENTITY_NOT_ACTIVE","AUTHENTICATION_POLICY_ABSENT",
                "AUDIENCE_MISMATCH","PURPOSE_MISMATCH","NONCE_MISMATCH","CONTEXT_HASH_MISMATCH","INVALID_TIME_RANGE","ASSERTION_LIFETIME_EXCEEDED",
                "ASSERTION_EXPIRED","ASSERTION_NOT_YET_VALID","UNAUTHORIZED_AUTHENTICATION_PROOF","DUPLICATE_AUTHENTICATION_PROOF",
                "UNAUTHORIZED_AUTHENTICATION_PROOF","INVALID_AUTHENTICATION_SIGNATURE","AUTHENTICATION_POLICY_NOT_SATISFIED",
                "PURPOSE_MISMATCH","AUDIENCE_MISMATCH","INVALID_AUTHENTICATION_GENERATION","INVALID_AUTHENTICATION_ASSERTION",
                "INVALID_AUTHENTICATION_ASSERTION","INVALID_AUTHENTICATION_ASSERTION"};
        Map<String,JsonNode> m=new HashMap<>();
        for(int i=0;i<31;i++){JsonNode v=xs.get(i);String id=String.format("AAI%02d",i+1);require(id+" stable error",id.equals(v.path("id").asText())&&errors[i].equals(v.path("expectedError").asText()));m.put(id,v);}
        JsonNode i1=m.get("AAI01");Key k=new Key("OpenIdentity OI-015 invalid authentication seed");
        require("AAI01 historical signature cryptographically verifies",k.verify(hex(i1.path("signingBytesHex").asText()),hex(i1.path("signatureHex").asText())));
        require("AAI01 historical StateHash is not current",!i1.path("historicalStateHashHex").asText().equals(i1.path("currentStateHashHex").asText()));
        JsonNode i2=m.get("AAI02");require("AAI02 authentication generation stale",i2.path("assertedGeneration").asLong()!=i2.path("currentGeneration").asLong());
        require("AAI03 identity DEACTIVATED","DEACTIVATED".equals(m.get("AAI03").path("currentStatus").asText()));
        require("AAI04 AuthenticationPolicy absent",!m.get("AAI04").path("authenticationPolicyPresent").asBoolean());
        require("AAI05 audience mismatch",!m.get("AAI05").path("expectedAudienceHex").asText().equals(m.get("AAI05").path("assertedAudienceHex").asText()));
        require("AAI06 purpose mismatch",!m.get("AAI06").path("expectedPurpose").asText().equals(m.get("AAI06").path("assertedPurpose").asText()));
        require("AAI07 nonce mismatch",!m.get("AAI07").path("expectedNonceHex").asText().equals(m.get("AAI07").path("assertedNonceHex").asText()));
        require("AAI08 contextHash mismatch",!m.get("AAI08").path("expectedContextHashHex").asText().equals(m.get("AAI08").path("assertedContextHashHex").asText()));
        require("AAI09 invalid zero time range",m.get("AAI09").path("expiresAt").asLong()<=m.get("AAI09").path("issuedAt").asLong());
        require("AAI10 lifetime exceeds 300",m.get("AAI10").path("expiresAt").asLong()-m.get("AAI10").path("issuedAt").asLong()>m.get("AAI10").path("maximumLifetime").asLong());
        require("AAI11 expiresAt boundary is expired",m.get("AAI11").path("verificationTime").asLong()>=m.get("AAI11").path("expiresAt").asLong());
        require("AAI12 before issuedAt",m.get("AAI12").path("verificationTime").asLong()<m.get("AAI12").path("issuedAt").asLong());
        JsonNode i13=m.get("AAI13");boolean auth13=false;for(JsonNode x:i13.path("authenticationMethodIdsHex"))if(x.asText().equals(i13.path("submittedMethodIdHex").asText()))auth13=true;
        require("AAI13 controller method not in AuthenticationPolicy",!auth13);
        JsonNode i14=m.get("AAI14");require("AAI14 duplicate proof method",i14.path("submittedMethodIdsHex").get(0).asText().equals(i14.path("submittedMethodIdsHex").get(1).asText()));
        JsonNode i15=m.get("AAI15");Set<String> auth15=new HashSet<>();for(JsonNode x:i15.path("authorizedMethodIdsHex"))auth15.add(x.asText());
        int authorizedSubmitted=0;boolean unauthorizedExtra=false;for(JsonNode x:i15.path("submittedMethodIdsHex")){if(auth15.contains(x.asText()))authorizedSubmitted++;else unauthorizedExtra=true;}
        require("AAI15 threshold is otherwise satisfied",authorizedSubmitted>=i15.path("authorizedThreshold").asInt());
        require("AAI15 unauthorized extra method exists",unauthorizedExtra);
        JsonNode i16=m.get("AAI16");Key ka=new Key("OpenIdentity OI-015 proof attack A seed");
        require("AAI16 valid baseline signature verifies",ka.verify(hex(i16.path("signingBytesHex").asText()),hex(i16.path("validSignatureHex").asText())));
        require("AAI16 corrupted signature rejected",!ka.verify(hex(i16.path("signingBytesHex").asText()),hex(i16.path("invalidSignatureHex").asText())));
        JsonNode i17=m.get("AAI17");require("AAI17 threshold not satisfied",i17.path("submittedMethodIdsHex").size()<i17.path("threshold").asInt());
        Key replay=new Key("OpenIdentity OI-015 replay authentication seed");
        for(String id:new String[]{"AAI18","AAI19","AAI20"}){JsonNode x=m.get(id);require(id+" replay signature cryptographically valid",replay.verify(hex(x.path("signingBytesHex").asText()),hex(x.path("signatureHex").asText())));}
        require("AAI18 purpose replay rejected",!m.get("AAI18").path("signedPurpose").asText().equals(m.get("AAI18").path("requestedPurpose").asText()));
        require("AAI19 audience replay rejected",!m.get("AAI19").path("signedAudienceHex").asText().equals(m.get("AAI19").path("requestedAudienceHex").asText()));
        require("AAI20 reset generation invalidates assertion",m.get("AAI20").path("assertedGeneration").asLong()!=m.get("AAI20").path("currentGeneration").asLong());
        require("AAI20 post-reset StateHash differs",!m.get("AAI20").path("preResetStateHashHex").asText().equals(m.get("AAI20").path("postResetStateHashHex").asText()));
        require("AAI21 purpose violates lowercase ASCII grammar",!m.get("AAI21").path("purpose").asText().matches("^[a-z0-9](?:[a-z0-9._-]{0,253}[a-z0-9])?$"));
        require("AAI22 nonce below minimum",m.get("AAI22").path("nonceLength").asInt()<m.get("AAI22").path("minimumNonceLength").asInt());
        require("AAI23 unsupported contextHash multihash",m.get("AAI23").path("submittedMultihashCode").asInt()!=m.get("AAI23").path("expectedMultihashCode").asInt());
        require("AAI24 unsupported assertion version",m.get("AAI24").path("assertionVersion").asInt()!=m.get("AAI24").path("supportedVersion").asInt());
        require("AAI25 identity mismatch",!m.get("AAI25").path("assertedIdentityHex").asText().equals(m.get("AAI25").path("currentStateIdentityHex").asText()));
        JsonNode i26=m.get("AAI26");byte[] p260=hex(i26.path("submittedMethodIdsHex").get(0).asText()),p261=hex(i26.path("submittedMethodIdsHex").get(1).asText());
        require("AAI26 proof order noncanonical",Arrays.compareUnsigned(p260,p261)>0);
        require("AAI27 nonce above maximum",m.get("AAI27").path("nonceLength").asInt()>m.get("AAI27").path("maximumNonceLength").asInt());
        require("AAI28 audience above maximum",m.get("AAI28").path("audienceLength").asInt()>m.get("AAI28").path("maximumAudienceLength").asInt());
        require("AAI29 unsupported StateHash multihash",m.get("AAI29").path("submittedMultihashCode").asInt()!=m.get("AAI29").path("expectedMultihashCode").asInt());
        JsonNode i30=m.get("AAI30");require("AAI30 uint64 maximum zero range",i30.path("expiresAt").bigIntegerValue().compareTo(i30.path("issuedAt").bigIntegerValue())<=0);
        JsonNode i31=m.get("AAI31");java.math.BigInteger life31=i31.path("expiresAt").bigIntegerValue().subtract(i31.path("issuedAt").bigIntegerValue());
        require("AAI31 exact uint64-safe lifetime is 301",life31.equals(java.math.BigInteger.valueOf(301))&&i31.path("exactLifetime").asInt()==301);
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
        require("vector count",d.path("vectors").size()==6);
        verifyAA01(d.path("vectors").get(0));verifyAA02(d.path("vectors").get(1));verifyAA03(d.path("vectors").get(2));verifyAA04(d.path("vectors").get(3));verifyAA05(d.path("vectors").get(4));verifyAA06(d.path("vectors").get(5));verifyInvalids(d);
        System.out.println("\n============================================");
        System.out.println("OI-015 AUTHENTICATION ASSERTION v1 JAVA AA01-AA06 + AAI01-AAI31 VERIFIED");
        System.out.println("============================================");
    }
}
