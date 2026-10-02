#!/usr/bin/env python3
"""Static/build gate for the OpenIdentity OAuth2/OIDC reference integration."""
from pathlib import Path
import subprocess,sys,re
ROOT=Path(__file__).resolve().parents[1]
MVN=sys.argv[1] if len(sys.argv)>1 else ("mvn.cmd" if sys.platform.startswith("win") else "mvn")
EXPECTED="99e2da9324adadb2f18350e1b95d9e491a502f4a91e12857cd7c092c0b0e62f3"

def run(label,*args,cwd):
 print(f"\n=== {label} ===",flush=True)
 subprocess.run(args,cwd=cwd,check=True)

def require(path,*needles):
 text=(ROOT/path).read_text(encoding="utf-8")
 for n in needles:
  if n not in text: raise SystemExit(f"FAIL {path}: missing {n!r}")
 print(f"PASS {path}")

run("Java SDK",MVN,"clean","install",cwd=ROOT/"java-sdk")
run("Authorization Server reference",MVN,"clean","package",cwd=ROOT/"samples/spring-authorization-server-reference")
run("OIDC client reference",MVN,"clean","package",cwd=ROOT/"samples/spring-oidc-client-reference")
require("samples/spring-authorization-server-reference/src/main/java/org/openidentity/samples/authserver/AuthorizationServerReferenceApplication.java",
 "AuthorizationGrantType.AUTHORIZATION_CODE","ClientAuthenticationMethod.NONE","requireProofKey(true)","scope(\"openid\")","new OpenIdentityJwtCustomizer()")
require("samples/spring-authorization-server-reference/src/main/java/org/openidentity/samples/authserver/DevelopmentOpenIdentityPrincipalConfiguration.java",
 EXPECTED,"ROLE_OPENIDENTITY")
require("samples/spring-oidc-client-reference/src/main/resources/application.yml",
 "issuer-uri: http://127.0.0.1:9000","client-authentication-method: none","authorization-grant-type: authorization_code","scope: openid,profile","OPENIDENTITY_CLIENT_SESSION")
require("samples/spring-authorization-server-reference/src/main/resources/application.yml","OPENIDENTITY_AUTH_SERVER_SESSION")
require("java-sdk/openidentity-spring-authorization-server/src/main/java/org/openidentity/spring/OpenIdentityJwtCustomizer.java","context.getClaims().subject(subject)")
print("\nOPENIDENTITY OAUTH2/OIDC REFERENCE GATE: PASS")
print("Expected OIDC subject:",EXPECTED)
