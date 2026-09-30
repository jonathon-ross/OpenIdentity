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
    return out

def main():
    d={"specification":"OpenIdentity OAuth 2.0 Delegated Agent Profile v1","status":"DRAFT-NON-NORMATIVE",
       "vectors":[px01()],"invalidVectors":invalids()}
    OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_text(json.dumps(d,indent=2)+"\n",encoding="utf-8",newline="\n")
    print("Wrote",OUT.relative_to(ROOT));print("PX01 GENERATED");print("PXI01-PXI08 GENERATED")
if __name__=="__main__":main()
