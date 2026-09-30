package org.openidentity.vectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public final class OAuthDelegatedAgentProfileV1Vectors {
    static final ObjectMapper JSON=new ObjectMapper();
    static void require(String n,boolean v){if(!v)throw new AssertionError(n);System.out.println("  "+n+": PASS");}
    static byte[] sha(byte[] b)throws Exception{return MessageDigest.getInstance("SHA-256").digest(b);}
    static byte[] seq(int start,int n){byte[] b=new byte[n];for(int i=0;i<n;i++)b[i]=(byte)(start+i);return b;}
    static String hx(byte[] b){return HexFormat.of().formatHex(b);}
    static Path find()throws Exception{
        Path d=Paths.get("").toAbsolutePath().normalize();
        for(int i=0;i<8&&d!=null;i++,d=d.getParent()){Path p=d.resolve("test-vectors/generated/oauth-delegated-agent-profile-v1.json");if(Files.isRegularFile(p))return p;}
        throw new NoSuchFileException("Could not locate oauth-delegated-agent-profile-v1.json");
    }
    public static void main(String[] args)throws Exception{
        JsonNode d=JSON.readTree(Files.readString(find()));
        require("suite specification","OpenIdentity OAuth 2.0 Delegated Agent Profile v1".equals(d.path("specification").asText()));
        require("draft status","DRAFT-NON-NORMATIVE".equals(d.path("status").asText()));
        require("PX01 only",d.path("vectors").size()==1&&"PX01".equals(d.path("vectors").get(0).path("id").asText()));
        JsonNode v=d.path("vectors").get(0),decision=v.path("expectedDecision"),jwt=v.path("expectedJwtProjection");
        byte[] root=seq(0,32),actor=seq(32,32);
        String jkt=Base64.getUrlEncoder().withoutPadding().encodeToString(sha("OpenIdentity PX01 DPoP key".getBytes(StandardCharsets.UTF_8)));
        long now=2004000000L,parent=now+240,child=now+180,max=300,exp=Math.min(Math.min(parent,child),now+max);
        String target="https://api.example.test/";
        require("PX01 subject derives rootGrantor",decision.path("subjectIdentityHex").asText().equals(hx(root)));
        require("PX01 actor derives terminal delegate",decision.path("actorIdentityHex").asText().equals(hx(actor)));
        require("PX01 read pair mapped",v.path("allowedTargetScopePairs").path(target).has("records.read"));
        require("PX01 write pair mapped",v.path("allowedTargetScopePairs").path(target).has("records.write"));
        require("PX01 DPoP jkt derives expected key",decision.path("dpopJkt").asText().equals(jkt));
        require("PX01 exp clipped by earliest delegation expiry",decision.path("expiresAt").asLong()==exp&&exp==child);
        require("PX01 exp does not exceed deployment max",exp<=now+max);
        require("PX01 no refresh token",!v.path("refreshTokenExpected").asBoolean()&&!decision.path("refreshTokenIssued").asBoolean());
        require("PX01 JWT sub",jwt.path("sub").asText().equals(hx(root)));
        require("PX01 JWT act.sub",jwt.path("act").path("sub").asText().equals(hx(actor)));
        require("PX01 JWT audience",jwt.path("aud").size()==1&&target.equals(jwt.path("aud").get(0).asText()));
        require("PX01 JWT scope","records.read records.write".equals(jwt.path("scope").asText()));
        require("PX01 JWT cnf.jkt",jkt.equals(jwt.path("cnf").path("jkt").asText()));
        require("PX01 JWT exp",jwt.path("exp").asLong()==exp);
        System.out.println("\n============================================");
        System.out.println("OPENIDENTITY OAUTH DELEGATED AGENT PROFILE v1 JAVA PX01 VERIFIED");
        System.out.println("============================================");
    }
}
