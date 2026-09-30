#!/usr/bin/env python3
"""Generate draft OpenIdentity OAuth Delegated Agent Profile runtime vectors."""
import base64,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/"test-vectors"/"generated"/"oauth-delegated-agent-profile-v1.json"
def h(b):return hashlib.sha256(b).digest()
def mh(b):return b"\x12\x20"+h(b)
def px01():
    root=bytes(range(32));actor=bytes(range(32,64))
    jkt=base64.urlsafe_b64encode(h(b"OpenIdentity PX01 DPoP key")).rstrip(b"=").decode()
    now=2004000000
    parent_exp=now+240
    child_exp=now+180
    deployment_max=300
    target="https://api.example.test/"
    requested=["records.read","records.write"]
    # Pinned capability-profile fixture: both requested pairs are explicitly allowed.
    allowed={
      target:{
        "records.read":{"capabilityId":"records.read","resourceConstraint":"tenant/alpha/*"},
        "records.write":{"capabilityId":"records.write","resourceConstraint":"tenant/alpha/record/42"}
      }
    }
    effective_exp=min(parent_exp,child_exp,now+deployment_max)
    decision={
      "subjectIdentityHex":root.hex(),
      "actorIdentityHex":actor.hex(),
      "audiences":[target],
      "scopes":sorted(requested),
      "dpopJkt":jkt,
      "issuedAt":now,
      "expiresAt":effective_exp,
      "refreshTokenIssued":False
    }
    return {
      "id":"PX01","description":"Successful delegated-agent authorization decision and JWT projection inputs","expected":"PASS",
      "rootGrantorHex":root.hex(),"terminalDelegateHex":actor.hex(),
      "verificationTime":now,"parentExpiresAt":parent_exp,"childExpiresAt":child_exp,
      "maximumAccessTokenLifetimeSeconds":deployment_max,
      "resolvedTargets":[target],"requestedScopes":sorted(requested),
      "allowedTargetScopePairs":allowed,"dpopJkt":jkt,
      "expectedDecision":decision,
      "expectedJwtProjection":{"sub":root.hex(),"act":{"sub":actor.hex()},"aud":[target],
          "scope":" ".join(sorted(requested)),"cnf":{"jkt":jkt},"iat":now,"exp":effective_exp},
      "refreshTokenExpected":False
    }


def px02():
    return {"id":"PX02","description":"Delegated-agent discovery metadata","expected":"PASS",
      "dpopRequired":True,"refreshSupported":False,"maxLifetimeSeconds":300}

def px03():
    return {"id":"PX03","description":"Safe public error projection","expected":"PASS",
      "internalError":"DELEGATION_NOT_CURRENTLY_USABLE","publicError":"invalid_request",
      "publicDescription":"The token exchange request could not be accepted."}

def invalids():
    out=[]
    def add(i,e,a,**kw):out.append({"id":i,"expectedError":e,"attack":a,**kw})
    subject_type="https://openidentity.org/oauth/token-type/delegated-subject-v1"
    actor_type="https://openidentity.org/oauth/token-type/authentication-assertion-v1"
    add("PXI01","INVALID_SUBJECT_TOKEN_TYPE","wrong-subject-token-type",
        submitted="urn:ietf:params:oauth:token-type:jwt",required=subject_type)
    add("PXI02","INVALID_ACTOR_TOKEN_TYPE","wrong-actor-token-type",
        submitted="urn:ietf:params:oauth:token-type:jwt",required=actor_type)
    add("PXI03","INVALID_SUBJECT_TOKEN_TRANSPORT","subject-token-base64url-padding",
        submitted="YWJjZA==",paddingPresent=True)
    add("PXI04","INVALID_ACTOR_TOKEN_TRANSPORT","actor-token-invalid-base64url-character",
        submitted="YWJj+ZA",invalidCharacter="+")
    add("PXI05","DPOP_REQUIRED","missing-dpop-proof",dpopPresent=False,required=True)
    base=px01();expected=base["dpopJkt"]
    other=base64.urlsafe_b64encode(h(b"OpenIdentity PXI06 substituted DPoP key")).rstrip(b"=").decode()
    add("PXI06","DPOP_CONTEXT_MISMATCH","validated-dpop-key-differs-from-context",
        contextDpopJkt=expected,validatedDpopJkt=other)
    add("PXI07","DPOP_TOKEN_BINDING_MISMATCH","issued-token-bound-to-different-key",
        contextDpopJkt=expected,validatedDpopJkt=expected,issuedTokenDpopJkt=other)
    add("PXI08","REFRESH_TOKEN_NOT_ALLOWED","refresh-token-issuance-attempt",
        profile="delegated-agent-v1",refreshTokenRequestedOrIssued=True,refreshTokensAllowed=False)
    # PXI09-PXI17: authorization, current-state, and cross-object binding failures.
    add("PXI09","SCOPE_NOT_AUTHORIZED","requested-scope-not-mapped",
        target="https://api.example.test/",scope="records.delete",explicitlyAllowed=False)
    add("PXI10","TARGET_NOT_AUTHORIZED","requested-target-not-authorized",
        target="https://admin.example.test/",scope="records.read",explicitlyAllowed=False)
    add("PXI11","TARGET_SCOPE_PAIR_NOT_AUTHORIZED","cartesian-product-partial-failure",
        targets=["https://api-a.example.test/","https://api-b.example.test/"],
        scopes=["records.read","records.write"],
        pairResults=[
          {"target":"https://api-a.example.test/","scope":"records.read","allowed":True},
          {"target":"https://api-a.example.test/","scope":"records.write","allowed":True},
          {"target":"https://api-b.example.test/","scope":"records.read","allowed":True},
          {"target":"https://api-b.example.test/","scope":"records.write","allowed":False}
        ],atomicFulfillment=True)
    add("PXI12","CAPABILITY_PROFILE_MAPPING_UNAVAILABLE","required-profile-mapping-unavailable",
        profilePinned=True,mappingAvailable=False)
    add("PXI13","AMBIGUOUS_TARGET","resource-audience-resolution-ambiguous",
        suppliedTarget="records-service",resolvedTargets=["https://api-a.example.test/","https://api-b.example.test/"])
    add("PXI14","DELEGATION_NOT_CURRENTLY_USABLE","authoritative-state-conclusive-denial",
        authoritativeStateAvailable=True,currentUsability=False)
    add("PXI15","DELEGATION_STATE_UNAVAILABLE","authoritative-state-unavailable",
        authoritativeStateAvailable=False,currentUsability=None)
    add("PXI16","ACTOR_BINDING_MISMATCH","oi015-identity-not-terminal-delegate",
        terminalDelegateHex=px01()["terminalDelegateHex"],oi015IdentityHex=bytes(range(1,33)).hex())
    add("PXI17","ASSERTION_CONTEXT_BINDING_MISMATCH","assertion-or-context-cross-binding-fails",
        actorAssertionIdMatches=False,contextHashMatches=False)
    # PXI18-PXI27: issuance/output invariants and safe public error projection.
    base=px01();dec=base["expectedDecision"];jwt=base["expectedJwtProjection"]
    add("PXI18","ACCESS_TOKEN_OUTLIVES_DELEGATION","exp-beyond-earliest-delegation-expiry",
        issuedExp=base["childExpiresAt"]+1,maximumAllowedExp=base["childExpiresAt"])
    add("PXI19","ACCESS_TOKEN_LIFETIME_EXCEEDED","exp-beyond-deployment-maximum",
        issuedExp=base["verificationTime"]+base["maximumAccessTokenLifetimeSeconds"]+1,
        maximumAllowedExp=base["verificationTime"]+base["maximumAccessTokenLifetimeSeconds"])
    add("PXI20","INVALID_SUBJECT_PROJECTION","jwt-sub-not-root-grantor",
        expectedSub=base["rootGrantorHex"],issuedSub=bytes(range(1,33)).hex())
    add("PXI21","INVALID_ACTOR_PROJECTION","jwt-act-sub-not-terminal-delegate",
        expectedActor=base["terminalDelegateHex"],issuedActor=bytes(range(1,33)).hex())
    add("PXI22","OUTPUT_SCOPE_AMPLIFICATION","issued-scope-not-authorized",
        authorizedScopes=base["requestedScopes"],issuedScopes=base["requestedScopes"]+["records.delete"])
    add("PXI23","OUTPUT_AUDIENCE_AMPLIFICATION","issued-audience-not-authorized",
        authorizedAudiences=base["resolvedTargets"],issuedAudiences=base["resolvedTargets"]+["https://admin.example.test/"])
    add("PXI24","MISSING_DPOP_CONFIRMATION","jwt-cnf-jkt-missing",
        expectedJkt=base["dpopJkt"],cnfJktPresent=False)
    other=base64.urlsafe_b64encode(h(b"OpenIdentity PXI25 wrong output DPoP key")).rstrip(b"=").decode()
    add("PXI25","DPOP_TOKEN_BINDING_MISMATCH","jwt-cnf-jkt-wrong",
        expectedJkt=base["dpopJkt"],issuedJkt=other)
    add("PXI26","REFRESH_TOKEN_NOT_ALLOWED","token-response-contains-refresh-token",
        refreshTokenPresent=True,refreshTokensAllowed=False)
    add("PXI27","SENSITIVE_ERROR_DISCLOSURE","public-error-leaks-internal-delegation-state",
        internalError="DELEGATION_NOT_CURRENTLY_USABLE",
        publicError="invalid_request",
        publicErrorDescription="GrantId abc is REVOKED",
        forbiddenDisclosure="REVOKED")
    add("PXI28","INVALID_GRANT_TYPE","wrong-grant-type",submitted="authorization_code",required="urn:ietf:params:oauth:grant-type:token-exchange")
    add("PXI29","CLIENT_AUTHENTICATION_REQUIRED","client-authentication-missing",required=True,authenticated=False)
    add("PXI30","INVALID_OI015_PURPOSE","oi015-purpose-mismatch",submitted="openidentity.other",required="openidentity.oauth.token-exchange")
    add("PXI31","INVALID_OI015_AUDIENCE","oi015-audience-mismatch",submitted="other-as",required="this-as")
    add("PXI32","ASSERTION_REPLAY","assertion-already-consumed",alreadyConsumed=True)
    add("PXI33","UNSUPPORTED_REQUESTED_TOKEN_TYPE","unsupported-output-token-type",supported=False)
    add("PXI34","INVALID_PUBLIC_ERROR_PROJECTION","target-failure-wrong-public-error",publicError="invalid_request",requiredPublicError="invalid_target")
    add("PXI35","INVALID_DISCOVERY_METADATA","dpop-advertised-false",advertised=False,required=True)
    add("PXI36","INVALID_DISCOVERY_METADATA","refresh-advertised-true",advertised=True,required=False)
    add("PXI37","INVALID_DISCOVERY_METADATA","advertised-lifetime-too-large",advertised=600,enforced=300)
    return out

def main():
    d={"specification":"OpenIdentity OAuth 2.0 Delegated Agent Profile v1","status":"DRAFT-NON-NORMATIVE",
       "vectors":[px01(),px02(),px03()],"invalidVectors":invalids()}
    OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_text(json.dumps(d,indent=2)+"\n",encoding="utf-8",newline="\n")
    print("Wrote",OUT.relative_to(ROOT));print("PX01-PX03 GENERATED");print("PXI01-PXI37 GENERATED")
if __name__=="__main__":main()
