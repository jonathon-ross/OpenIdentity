package org.openidentity.vectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public final class OAuthTokenExchangeContextV1Vectors {
    static final ObjectMapper JSON=new ObjectMapper();
    static void require(String n,boolean v){if(!v)throw new AssertionError(n);System.out.println("  "+n+": PASS");}
    static byte[] sha(byte[] b)throws Exception{return MessageDigest.getInstance("SHA-256").digest(b);}
    static byte[] mh(byte[] b)throws Exception{byte[] d=sha(b),o=new byte[34];o[0]=0x12;o[1]=0x20;System.arraycopy(d,0,o,2,32);return o;}
    static String hx(byte[] b){return HexFormat.of().formatHex(b);}
    record E(byte[] b){}
    static E E(byte[] b){return new E(b);}
    static void write(DeterministicCborWriter w,Object x){
        if(x instanceof Integer i)w.writeUnsigned(i);
        else if(x instanceof byte[] b)w.writeByteString(b);
        else if(x instanceof E e)w.writeEncoded(e.b);
        else throw new IllegalArgumentException("Unsupported "+x.getClass());
    }
    static byte[] map(Object... kv){DeterministicCborWriter w=new DeterministicCborWriter();w.writeMapHeader(kv.length/2);for(int i=0;i<kv.length;i+=2){w.writeUnsigned((Integer)kv[i]);write(w,kv[i+1]);}return w.toByteArray();}
    static byte[] arr(byte[][] xs){DeterministicCborWriter w=new DeterministicCborWriter();w.writeArrayHeader(xs.length);for(byte[] x:xs)w.writeByteString(x);return w.toByteArray();}
    static byte[][] sorted(String... xs){byte[][] a=new byte[xs.length][];for(int i=0;i<xs.length;i++)a[i]=xs[i].getBytes(StandardCharsets.UTF_8);Arrays.sort(a,Arrays::compareUnsigned);return a;}
    static Path findVectorFile()throws Exception{
        Path d=Paths.get("").toAbsolutePath().normalize();
        for(int i=0;i<8&&d!=null;i++,d=d.getParent()){Path p=d.resolve("test-vectors/generated/oauth-token-exchange-context-v1.json");if(Files.isRegularFile(p))return p;}
        throw new NoSuchFileException("Could not locate oauth-token-exchange-context-v1.json");
    }
    public static void main(String[] args)throws Exception{
        JsonNode d=JSON.readTree(Files.readString(findVectorFile()));require("suite specification","OpenIdentity OAuth Token Exchange Context v1".equals(d.path("specification").asText()));
        require("draft status","DRAFT-NON-NORMATIVE".equals(d.path("status").asText()));require("vector IDs TX01-TX04",d.path("vectors").size()==4&&"TX01".equals(d.path("vectors").get(0).path("id").asText())&&"TX04".equals(d.path("vectors").get(3).path("id").asText()));
        JsonNode v=d.path("vectors").get(0);byte[] eid=mh("OpenIdentity OAuth TX01 delegation evidence".getBytes(StandardCharsets.UTF_8));
        byte[] jkt=Base64.getUrlEncoder().withoutPadding().encode(sha("OpenIdentity OAuth TX01 DPoP public JWK".getBytes(StandardCharsets.UTF_8)));
        byte[][] resources=sorted("https://api.example.test/v2","https://api.example.test/v1");
        byte[][] audiences=sorted("records-service","audit-service"),scopes=sorted("records.write","records.read");
        require("TX01 resources canonical order",v.path("resources").get(0).asText().equals(new String(resources[0],StandardCharsets.UTF_8)));
        require("TX01 audiences canonical order",v.path("audiences").get(0).asText().equals(new String(audiences[0],StandardCharsets.UTF_8)));
        require("TX01 scopes canonical order",v.path("scopes").get(0).asText().equals(new String(scopes[0],StandardCharsets.UTF_8)));
        require("TX01 DPoP jkt length",jkt.length==43&&v.path("dpopJkt").asText().equals(new String(jkt,StandardCharsets.US_ASCII)));
        byte[] ctx=map(1,1,2,"https://as.example.test".getBytes(StandardCharsets.UTF_8),3,"agent-client-016".getBytes(StandardCharsets.UTF_8),
                4,"urn:ietf:params:oauth:token-type:access_token".getBytes(StandardCharsets.UTF_8),5,E(arr(resources)),6,E(arr(audiences)),7,E(arr(scopes)),8,eid,9,jkt);
        require("TX01 context bytes",v.path("contextBytesHex").asText().equals(hx(ctx)));require("TX01 contextHash",v.path("contextHashHex").asText().equals(hx(mh(ctx))));
        JsonNode xs=d.path("invalidVectors");require("invalid vector count",xs.size()==26);
        String[] errors={"INVALID_CONTEXT_VERSION","DUPLICATE_SCOPE","NONCANONICAL_SCOPE_ORDER","DUPLICATE_RESOURCE","NONCANONICAL_RESOURCE_ORDER",
                "INVALID_RESOURCE","INVALID_RESOURCE","DUPLICATE_AUDIENCE","NONCANONICAL_AUDIENCE_ORDER","INVALID_SCOPE",
                "INVALID_DELEGATION_EVIDENCE_ID","INVALID_DPOP_JKT","INVALID_DPOP_JKT","TOO_MANY_RESOURCES","TOO_MANY_AUDIENCES","TOO_MANY_SCOPES",
                "INVALID_AUTHORIZATION_SERVER","INVALID_CLIENT_ID","INVALID_REQUESTED_TOKEN_TYPE","INVALID_RESOURCE","INVALID_AUDIENCE","INVALID_SCOPE",
                "INVALID_DELEGATION_EVIDENCE_ID","INVALID_DELEGATION_EVIDENCE_ID","INVALID_DPOP_JKT","INVALID_DPOP_JKT"};
        Map<String,JsonNode> m=new HashMap<>();for(int i=0;i<xs.size();i++){JsonNode x=xs.get(i);String id=String.format("TXI%02d",i+1);
            require(id+" stable error",id.equals(x.path("id").asText())&&errors[i].equals(x.path("expectedError").asText()));m.put(id,x);}
        require("TXI01 unsupported version",m.get("TXI01").path("submittedVersion").asInt()!=m.get("TXI01").path("supportedVersion").asInt());
        require("TXI02 duplicate scope",m.get("TXI02").path("scopes").get(0).asText().equals(m.get("TXI02").path("scopes").get(1).asText()));
        require("TXI03 scope order noncanonical",!m.get("TXI03").path("scopes").toString().equals(m.get("TXI03").path("canonicalScopes").toString()));
        require("TXI04 duplicate resource",m.get("TXI04").path("resources").get(0).asText().equals(m.get("TXI04").path("resources").get(1).asText()));
        require("TXI05 resource order noncanonical",!m.get("TXI05").path("resources").toString().equals(m.get("TXI05").path("canonicalResources").toString()));
        require("TXI06 relative resource rejected",m.get("TXI06").path("resource").asText().startsWith("/"));
        require("TXI07 resource fragment rejected",m.get("TXI07").path("resource").asText().contains("#"));
        require("TXI08 duplicate audience",m.get("TXI08").path("audiences").get(0).asText().equals(m.get("TXI08").path("audiences").get(1).asText()));
        require("TXI09 audience order noncanonical",!m.get("TXI09").path("audiences").toString().equals(m.get("TXI09").path("canonicalAudiences").toString()));
        require("TXI10 scope contains forbidden space",m.get("TXI10").path("scope").asText().contains(" "));
        require("TXI11 wrong DelegationEvidenceId multihash",m.get("TXI11").path("submittedMultihashCode").asInt()!=m.get("TXI11").path("expectedMultihashCode").asInt());
        require("TXI12 DPoP jkt mandatory",m.get("TXI12").path("required").asBoolean()&&!m.get("TXI12").path("dpopJktPresent").asBoolean());
        require("TXI13 DPoP jkt exact length",m.get("TXI13").path("dpopJktLength").asInt()!=m.get("TXI13").path("requiredLength").asInt());
        require("TX02 exact resource count",d.path("vectors").get(1).path("resourceCount").asInt()==16);
        require("TX03 exact audience count",d.path("vectors").get(2).path("audienceCount").asInt()==16);
        require("TX04 exact scope count",d.path("vectors").get(3).path("scopeCount").asInt()==64);
        for(String id:new String[]{"TXI14","TXI15","TXI16"})require(id+" count over limit",m.get(id).path("count").asInt()==m.get(id).path("maximum").asInt()+1);
        for(String id:new String[]{"TXI17","TXI18","TXI19","TXI20","TXI21","TXI22"})require(id+" length over limit",m.get(id).path("length").asInt()==m.get(id).path("maximum").asInt()+1);
        require("TXI23 wrong digest-length prefix",m.get("TXI23").path("submittedDigestLengthPrefix").asInt()!=m.get("TXI23").path("requiredDigestLengthPrefix").asInt());
        require("TXI24 wrong multihash total length",m.get("TXI24").path("submittedLength").asInt()!=m.get("TXI24").path("requiredLength").asInt());
        require("TXI25 invalid base64url character",m.get("TXI25").path("dpopJkt").asText().contains("+"));
        require("TXI26 base64url padding forbidden",m.get("TXI26").path("dpopJkt").asText().contains("="));
        System.out.println("\n============================================");System.out.println("OPENIDENTITY OAUTH TOKEN EXCHANGE CONTEXT v1 JAVA TX01-TX04 + TXI01-TXI26 VERIFIED");System.out.println("============================================");
    }
}
