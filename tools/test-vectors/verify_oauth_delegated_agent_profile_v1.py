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
    print("\n============================================");print("OPENIDENTITY OAUTH DELEGATED AGENT PROFILE v1 PX01 VERIFIED");print("============================================")
if __name__=="__main__":main()
