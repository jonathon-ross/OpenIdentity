#!/usr/bin/env python3
"""Independently verify delegated-agent profile PX01."""
import base64,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];P=ROOT/"test-vectors"/"generated"/"oauth-delegated-agent-profile-v1.json"
def h(b):return hashlib.sha256(b).digest()
def req(n,v):
    if not v:raise AssertionError(n)
    print(" ",n+": PASS")
def main():
    d=json.loads(P.read_text());req("suite specification",d["specification"]=="OpenIdentity OAuth 2.0 Delegated Agent Profile v1")
    req("draft status",d["status"]=="DRAFT-NON-NORMATIVE");req("PX01 only",[x["id"] for x in d["vectors"]]==["PX01"])
    v=d["vectors"][0];root=bytes(range(32));actor=bytes(range(32,64))
    jkt=base64.urlsafe_b64encode(h(b"OpenIdentity PX01 DPoP key")).rstrip(b"=").decode()
    now=2004000000;parent=now+240;child=now+180;mx=300;exp=min(parent,child,now+mx)
    target="https://api.example.test/";scopes=["records.read","records.write"]
    req("PX01 subject derives rootGrantor",v["expectedDecision"]["subjectIdentityHex"]==root.hex())
    req("PX01 actor derives terminal delegate",v["expectedDecision"]["actorIdentityHex"]==actor.hex())
    req("PX01 all target/scope pairs explicitly mapped",all(s in v["allowedTargetScopePairs"][target] for s in scopes))
    req("PX01 DPoP jkt derives expected key",v["expectedDecision"]["dpopJkt"]==jkt)
    req("PX01 exp clipped by earliest delegation expiry",v["expectedDecision"]["expiresAt"]==exp==child)
    req("PX01 exp does not exceed deployment max",exp<=now+mx)
    req("PX01 no refresh token",v["refreshTokenExpected"] is False and v["expectedDecision"]["refreshTokenIssued"] is False)
    jwt=v["expectedJwtProjection"];req("PX01 JWT sub",jwt["sub"]==root.hex());req("PX01 JWT act.sub",jwt["act"]["sub"]==actor.hex())
    req("PX01 JWT audience",jwt["aud"]==[target]);req("PX01 JWT scope",jwt["scope"]=="records.read records.write")
    req("PX01 JWT cnf.jkt",jwt["cnf"]["jkt"]==jkt);req("PX01 JWT exp",jwt["exp"]==exp)
    inv={x["id"]:x for x in d["invalidVectors"]};req("invalid vector IDs PXI01-PXI08",set(inv)=={f"PXI{i:02d}" for i in range(1,9)})
    errors=["INVALID_SUBJECT_TOKEN_TYPE","INVALID_ACTOR_TOKEN_TYPE","INVALID_SUBJECT_TOKEN_TRANSPORT","INVALID_ACTOR_TOKEN_TRANSPORT",
            "DPOP_REQUIRED","DPOP_CONTEXT_MISMATCH","DPOP_TOKEN_BINDING_MISMATCH","REFRESH_TOKEN_NOT_ALLOWED"]
    req("PXI01-PXI08 stable errors",all(inv[f"PXI{i:02d}"]["expectedError"]==errors[i-1] for i in range(1,9)))
    req("PXI01 exact subject token type required",inv["PXI01"]["submitted"]!=inv["PXI01"]["required"])
    req("PXI02 exact actor token type required",inv["PXI02"]["submitted"]!=inv["PXI02"]["required"])
    req("PXI03 base64url padding rejected",inv["PXI03"]["paddingPresent"] is True and "=" in inv["PXI03"]["submitted"])
    req("PXI04 non-base64url character rejected",inv["PXI04"]["invalidCharacter"] in inv["PXI04"]["submitted"])
    req("PXI05 DPoP mandatory",inv["PXI05"]["required"] and not inv["PXI05"]["dpopPresent"])
    req("PXI06 DPoP/context mismatch",inv["PXI06"]["contextDpopJkt"]!=inv["PXI06"]["validatedDpopJkt"])
    req("PXI07 three-way DPoP binding mismatch",inv["PXI07"]["contextDpopJkt"]==inv["PXI07"]["validatedDpopJkt"]!=inv["PXI07"]["issuedTokenDpopJkt"])
    req("PXI08 refresh token prohibited",inv["PXI08"]["refreshTokenRequestedOrIssued"] and not inv["PXI08"]["refreshTokensAllowed"])

    print("\n============================================");print("OPENIDENTITY OAUTH DELEGATED AGENT PROFILE v1 PX01 + PXI01-PXI08 VERIFIED");print("============================================")
if __name__=="__main__":main()
