#!/usr/bin/env python3
"""Static/build gate for the OpenIdentity OAuth2/OIDC reference integration."""
from pathlib import Path
import subprocess,sys,re,os,time,urllib.request,tempfile,shutil
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

print("\n=== Native OI-015 OAuth2/OIDC live gate ===",flush=True)
state_dir=ROOT/"tmp/native-oi015-ci-state"
if state_dir.exists(): shutil.rmtree(state_dir)
state_dir.mkdir(parents=True)
fixture=subprocess.run([MVN,"-q","exec:java","-Dexec.mainClass=org.openidentity.samples.nativeauth.NativeOi015FixtureGenerator",f"-Dexec.args={state_dir}"],cwd=ROOT/"samples/native-oi015-signer",check=True,text=True,capture_output=True)
m=re.search(r'\\{[\\s\\S]*"identityHex"[\\s\\S]*\\}',fixture.stdout)
if not m: raise SystemExit("FAIL live gate: fixture JSON unavailable")
import json
material=json.loads(m.group(0))
env=os.environ.copy();env["OPENIDENTITY_STATE_DIR"]=str(state_dir)
server=subprocess.Popen([MVN,"spring-boot:run","-Dspring-boot.run.profiles=native-oi015"],cwd=ROOT/"samples/spring-authorization-server-reference",env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
try:
 deadline=time.time()+60
 ready=False
 while time.time()<deadline:
  if server.poll() is not None:
   output=server.stdout.read() if server.stdout else ""
   raise SystemExit("FAIL live gate: authorization server exited\n"+output)
  try:
   with urllib.request.urlopen("http://127.0.0.1:9000/.well-known/openid-configuration",timeout=1) as r:
    if r.status==200: ready=True;break
  except Exception: time.sleep(.5)
 if not ready: raise SystemExit("FAIL live gate: authorization server readiness timeout")
 args=" ".join(["http://127.0.0.1:9000",str(state_dir),material["identityHex"],material["methodIdHex"],material["privateSeedHex"]])
 live=subprocess.run([MVN,"-q","exec:java","-Dexec.mainClass=org.openidentity.samples.nativeauth.NativeOi015Flow",f"-Dexec.args={args}"],cwd=ROOT/"samples/native-oi015-signer",text=True,capture_output=True)
 print(live.stdout,flush=True)
 if live.returncode!=0:
  print(live.stderr,file=sys.stderr)
  raise SystemExit("FAIL live gate: NativeOi015Flow")
 if "NATIVE OI-015 -> OAUTH2/OIDC END-TO-END: PASS" not in live.stdout: raise SystemExit("FAIL live gate: PASS marker missing")
 if '"authorizationCodeReplayRejected" : true' not in live.stdout: raise SystemExit("FAIL live gate: authorization-code replay assertion missing")
 if '"wrongPkceRejected" : true' not in live.stdout: raise SystemExit("FAIL live gate: wrong-PKCE assertion missing")
 if '"identitySubstitutionRejected" : true' not in live.stdout: raise SystemExit("FAIL live gate: identity-substitution assertion missing")
finally:
 server.terminate()
 try: server.wait(timeout=10)
 except subprocess.TimeoutExpired:
  server.kill();server.wait(timeout=5)
 if state_dir.exists(): shutil.rmtree(state_dir)
print("\nOPENIDENTITY OAUTH2/OIDC REFERENCE GATE: PASS")
print("Expected OIDC subject:",EXPECTED)
