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
        require("vector IDs PX01-PX03",d.path("vectors").size()==3&&"PX01".equals(d.path("vectors").get(0).path("id").asText())&&"PX03".equals(d.path("vectors").get(2).path("id").asText()));
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
        JsonNode xs=d.path("invalidVectors");require("invalid vector count",xs.size()==37);
        String[] errors={"INVALID_SUBJECT_TOKEN_TYPE","INVALID_ACTOR_TOKEN_TYPE","INVALID_SUBJECT_TOKEN_TRANSPORT","INVALID_ACTOR_TOKEN_TRANSPORT",
                "DPOP_REQUIRED","DPOP_CONTEXT_MISMATCH","DPOP_TOKEN_BINDING_MISMATCH","REFRESH_TOKEN_NOT_ALLOWED",
                "SCOPE_NOT_AUTHORIZED","TARGET_NOT_AUTHORIZED","TARGET_SCOPE_PAIR_NOT_AUTHORIZED","CAPABILITY_PROFILE_MAPPING_UNAVAILABLE",
                "AMBIGUOUS_TARGET","DELEGATION_NOT_CURRENTLY_USABLE","DELEGATION_STATE_UNAVAILABLE","ACTOR_BINDING_MISMATCH","ASSERTION_CONTEXT_BINDING_MISMATCH",
                "ACCESS_TOKEN_OUTLIVES_DELEGATION","ACCESS_TOKEN_LIFETIME_EXCEEDED","INVALID_SUBJECT_PROJECTION","INVALID_ACTOR_PROJECTION",
                "OUTPUT_SCOPE_AMPLIFICATION","OUTPUT_AUDIENCE_AMPLIFICATION","MISSING_DPOP_CONFIRMATION","DPOP_TOKEN_BINDING_MISMATCH",
                "REFRESH_TOKEN_NOT_ALLOWED","SENSITIVE_ERROR_DISCLOSURE","INVALID_GRANT_TYPE","CLIENT_AUTHENTICATION_REQUIRED","INVALID_OI015_PURPOSE",
                "INVALID_OI015_AUDIENCE","ASSERTION_REPLAY","UNSUPPORTED_REQUESTED_TOKEN_TYPE","INVALID_PUBLIC_ERROR_PROJECTION",
                "INVALID_DISCOVERY_METADATA","INVALID_DISCOVERY_METADATA","INVALID_DISCOVERY_METADATA"};
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
        require("PXI18 token outlives delegation",m.get("PXI18").path("issuedExp").asLong()>m.get("PXI18").path("maximumAllowedExp").asLong());
        require("PXI19 token exceeds deployment maximum",m.get("PXI19").path("issuedExp").asLong()>m.get("PXI19").path("maximumAllowedExp").asLong());
        require("PXI20 subject projection mismatch",!m.get("PXI20").path("issuedSub").asText().equals(m.get("PXI20").path("expectedSub").asText()));
        require("PXI21 actor projection mismatch",!m.get("PXI21").path("issuedActor").asText().equals(m.get("PXI21").path("expectedActor").asText()));
        Set<String> a22=new HashSet<>();for(JsonNode x:m.get("PXI22").path("authorizedScopes"))a22.add(x.asText());boolean amp22=false;for(JsonNode x:m.get("PXI22").path("issuedScopes"))if(!a22.contains(x.asText()))amp22=true;
        require("PXI22 output scope amplification",amp22);
        Set<String> a23=new HashSet<>();for(JsonNode x:m.get("PXI23").path("authorizedAudiences"))a23.add(x.asText());boolean amp23=false;for(JsonNode x:m.get("PXI23").path("issuedAudiences"))if(!a23.contains(x.asText()))amp23=true;
        require("PXI23 output audience amplification",amp23);
        require("PXI24 DPoP confirmation mandatory",!m.get("PXI24").path("cnfJktPresent").asBoolean());
        require("PXI25 output DPoP key mismatch",!m.get("PXI25").path("issuedJkt").asText().equals(m.get("PXI25").path("expectedJkt").asText()));
        require("PXI26 response refresh token prohibited",m.get("PXI26").path("refreshTokenPresent").asBoolean()&&!m.get("PXI26").path("refreshTokensAllowed").asBoolean());
        require("PXI27 public error leaks internal state",m.get("PXI27").path("publicErrorDescription").asText().contains(m.get("PXI27").path("forbiddenDisclosure").asText()));
        require("PX02 DPoP advertised required",d.path("vectors").get(1).path("dpopRequired").asBoolean());
        require("PX02 refresh advertised false",!d.path("vectors").get(1).path("refreshSupported").asBoolean());
        require("PX02 lifetime advertised 300",d.path("vectors").get(1).path("maxLifetimeSeconds").asInt()==300);
        require("PX03 safe public error","invalid_request".equals(d.path("vectors").get(2).path("publicError").asText())&&!d.path("vectors").get(2).path("publicDescription").asText().contains("REVOKED"));
        require("PXI28 exact grant type required",!m.get("PXI28").path("submitted").asText().equals(m.get("PXI28").path("required").asText()));
        require("PXI29 client authentication prerequisite",m.get("PXI29").path("required").asBoolean()&&!m.get("PXI29").path("authenticated").asBoolean());
        require("PXI30 OI-015 purpose binding",!m.get("PXI30").path("submitted").asText().equals(m.get("PXI30").path("required").asText()));
        require("PXI31 OI-015 audience binding",!m.get("PXI31").path("submitted").asText().equals(m.get("PXI31").path("required").asText()));
        require("PXI32 assertion replay rejected",m.get("PXI32").path("alreadyConsumed").asBoolean());
        require("PXI33 requested token type unsupported",!m.get("PXI33").path("supported").asBoolean());
        require("PXI34 target failure projects invalid_target",!m.get("PXI34").path("publicError").asText().equals(m.get("PXI34").path("requiredPublicError").asText()));
        require("PXI35 discovery DPoP mismatch",m.get("PXI35").path("advertised").asBoolean()!=m.get("PXI35").path("required").asBoolean());
        require("PXI36 discovery refresh mismatch",m.get("PXI36").path("advertised").asBoolean()!=m.get("PXI36").path("required").asBoolean());
        require("PXI37 advertised lifetime exceeds enforced",m.get("PXI37").path("advertised").asInt()>m.get("PXI37").path("enforced").asInt());
        System.out.println("\n============================================");
        System.out.println("OPENIDENTITY OAUTH DELEGATED AGENT PROFILE v1 JAVA PX01-PX03 + PXI01-PXI37 VERIFIED");
        System.out.println("============================================");
    }
}
