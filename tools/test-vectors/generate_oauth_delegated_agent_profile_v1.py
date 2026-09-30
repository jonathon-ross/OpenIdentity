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
def main():
    d={"specification":"OpenIdentity OAuth 2.0 Delegated Agent Profile v1","status":"DRAFT-NON-NORMATIVE",
       "vectors":[px01()],"invalidVectors":[]}
    OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_text(json.dumps(d,indent=2)+"\n",encoding="utf-8",newline="\n")
    print("Wrote",OUT.relative_to(ROOT));print("PX01 GENERATED")
if __name__=="__main__":main()
