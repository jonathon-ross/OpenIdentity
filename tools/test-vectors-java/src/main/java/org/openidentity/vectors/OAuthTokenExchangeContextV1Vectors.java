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
        require("draft status","DRAFT-NON-NORMATIVE".equals(d.path("status").asText()));require("TX01 only",d.path("vectors").size()==1&&"TX01".equals(d.path("vectors").get(0).path("id").asText()));
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
        System.out.println("\n============================================");System.out.println("OPENIDENTITY OAUTH TOKEN EXCHANGE CONTEXT v1 JAVA TX01 VERIFIED");System.out.println("============================================");
    }
}
