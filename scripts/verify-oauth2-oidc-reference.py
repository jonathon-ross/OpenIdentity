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
run("Native OI-015 Spring authentication",MVN,"clean","test",cwd=ROOT/"java-sdk/openidentity-spring-authentication")
run("Authorization Server reference",MVN,"clean","package",cwd=ROOT/"samples/spring-authorization-server-reference")
run("OIDC client reference",MVN,"clean","package",cwd=ROOT/"samples/spring-oidc-client-reference")
run("Native OI-015 signer reference",MVN,"clean","package",cwd=ROOT/"samples/native-oi015-signer")
require("samples/spring-authorization-server-reference/src/main/java/org/openidentity/samples/authserver/AuthorizationServerReferenceApplication.java",
 "AuthorizationGrantType.AUTHORIZATION_CODE","ClientAuthenticationMethod.NONE","requireProofKey(true)","scope(\"openid\")","new OpenIdentityJwtCustomizer()","OpenIdentityActiveDirectorySecurityConfigurer","WWW-Authenticate\",\"Negotiate","openidentity.authorization-server.issuer")
require("samples/spring-authorization-server-reference/src/main/java/org/openidentity/samples/authserver/DevelopmentOpenIdentityPrincipalConfiguration.java",
 EXPECTED,"ROLE_OPENIDENTITY")
require("samples/spring-oidc-client-reference/src/main/resources/application.yml",
 "${OPENIDENTITY_OIDC_ISSUER:http://127.0.0.1:9000}","client-authentication-method: none","authorization-grant-type: authorization_code","scope: openid,profile","OPENIDENTITY_CLIENT_SESSION")
require("samples/spring-authorization-server-reference/src/main/resources/application.yml","OPENIDENTITY_AUTH_SERVER_SESSION")
require("samples/spring-authorization-server-reference/src/main/java/org/openidentity/samples/authserver/NativeOi015Configuration.java","native-oi015","Oi015Verifier","CanonicalAuthenticationStateResolver","OpenIdentityAuthenticationService")
require("samples/spring-authorization-server-reference/src/main/resources/application-microsoft-ad.yml",
 "enabled: true","HTTP/openidentity.oi-test.internal" if False else "OPENIDENTITY_KERBEROS_SERVICE_PRINCIPAL","OPENIDENTITY_KERBEROS_KEYTAB","OPENIDENTITY_STATE_DIR","OPENIDENTITY_AD_BINDING_STORE","http://openidentity.oi-test.internal:9000")
require("java-sdk/openidentity-spring-authorization-server/src/main/java/org/openidentity/spring/OpenIdentityJwtCustomizer.java","context.getClaims().subject(subject)")
print("\nOPENIDENTITY OAUTH2/OIDC REFERENCE GATE: PASS")
print("Expected OIDC subject:",EXPECTED)
