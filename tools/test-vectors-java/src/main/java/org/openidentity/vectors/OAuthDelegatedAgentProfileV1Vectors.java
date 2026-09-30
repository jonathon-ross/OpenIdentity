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
        JsonNode xs=d.path("invalidVectors");require("invalid vector count",xs.size()==17);
        String[] errors={"INVALID_SUBJECT_TOKEN_TYPE","INVALID_ACTOR_TOKEN_TYPE","INVALID_SUBJECT_TOKEN_TRANSPORT","INVALID_ACTOR_TOKEN_TRANSPORT",
                "DPOP_REQUIRED","DPOP_CONTEXT_MISMATCH","DPOP_TOKEN_BINDING_MISMATCH","REFRESH_TOKEN_NOT_ALLOWED",
                "SCOPE_NOT_AUTHORIZED","TARGET_NOT_AUTHORIZED","TARGET_SCOPE_PAIR_NOT_AUTHORIZED","CAPABILITY_PROFILE_MAPPING_UNAVAILABLE",
                "AMBIGUOUS_TARGET","DELEGATION_NOT_CURRENTLY_USABLE","DELEGATION_STATE_UNAVAILABLE","ACTOR_BINDING_MISMATCH","ASSERTION_CONTEXT_BINDING_MISMATCH"};
        Map<String,JsonNode> m=new HashMap<>();for(int i=0;i<xs.size();i++){JsonNode x=xs.get(i);String id=String.format("PXI%02d",i+1);
            require(id+" stable error",id.equals(x.path("id").asText())&&errors[i].equals(x.path("expectedError").asText()));m.put(id,x);}
        require("PXI01 exact subject token type required",!m.get("PXI01").path("submitted").asText().equals(m.get("PXI01").path("required").asText()));
        require("PXI02 exact actor token type required",!m.get("PXI02").path("submitted").asText().equals(m.get("PXI02").path("required").asText()));
        require("PXI03 base64url padding rejected",m.get("PXI03").path("paddingPresent").asBoolean()&&m.get("PXI03").path("submitted").asText().contains("="));
        require("PXI04 non-base64url character rejected",m.get("PXI04").path("submitted").asText().contains(m.get("PXI04").path("invalidCharacter").asText()));
        require("PXI05 DPoP mandatory",m.get("PXI05").path("required").asBoolean()&&!m.get("PXI05").path("dpopPresent").asBoolean());
        require("PXI06 DPoP/context mismatch",!m.get("PXI06").path("contextDpopJkt").asText().equals(m.get("PXI06").path("validatedDpopJkt").asText()));
        require("PXI07 three-way DPoP binding mismatch",m.get("PXI07").path("contextDpopJkt").asText().equals(m.get("PXI07").path("validatedDpopJkt").asText())&&!m.get("PXI07").path("validatedDpopJkt").asText().equals(m.get("PXI07").path("issuedTokenDpopJkt").asText()));
        require("PXI08 refresh token prohibited",m.get("PXI08").path("refreshTokenRequestedOrIssued").asBoolean()&&!m.get("PXI08").path("refreshTokensAllowed").asBoolean());
        require("PXI09 scope denied",!m.get("PXI09").path("explicitlyAllowed").asBoolean());
        require("PXI10 target denied",!m.get("PXI10").path("explicitlyAllowed").asBoolean());
        boolean anyDenied=false;for(JsonNode x:m.get("PXI11").path("pairResults"))if(!x.path("allowed").asBoolean())anyDenied=true;
        require("PXI11 Cartesian product atomic failure",m.get("PXI11").path("atomicFulfillment").asBoolean()&&anyDenied);
        require("PXI12 mapping unavailable fails closed",m.get("PXI12").path("profilePinned").asBoolean()&&!m.get("PXI12").path("mappingAvailable").asBoolean());
        require("PXI13 target resolution ambiguous",m.get("PXI13").path("resolvedTargets").size()>1);
        require("PXI14 conclusive current-state denial",m.get("PXI14").path("authoritativeStateAvailable").asBoolean()&&!m.get("PXI14").path("currentUsability").asBoolean());
        require("PXI15 current state unavailable",!m.get("PXI15").path("authoritativeStateAvailable").asBoolean());
        require("PXI16 actor identity binding fails",!m.get("PXI16").path("terminalDelegateHex").asText().equals(m.get("PXI16").path("oi015IdentityHex").asText()));
        require("PXI17 assertion/context binding fails",!m.get("PXI17").path("actorAssertionIdMatches").asBoolean()&&!m.get("PXI17").path("contextHashMatches").asBoolean());
        System.out.println("\n============================================");
        System.out.println("OPENIDENTITY OAUTH DELEGATED AGENT PROFILE v1 JAVA PX01 + PXI01-PXI17 VERIFIED");
        System.out.println("============================================");
    }
}
