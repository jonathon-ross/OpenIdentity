package org.openidentity.samples.ad;

import jakarta.servlet.http.HttpSession;
import org.openidentity.ad.*;
import org.openidentity.auth.*;
import org.openidentity.core.*;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;

@SpringBootApplication
@RestController
public class AdSimulatorApplication {
 static final String AD="SIMULATED_VERIFIED_AD_PRINCIPAL",PENDING="OPENIDENTITY_AD_PENDING",RESOLVED="OPENIDENTITY_AD_RESOLVED";
 record Pending(VerifiedAdPrincipal principal,ExternalAdBindingV1.Binding binding,byte[] challenge,byte[] audience,byte[] nonce,byte[] contextHash){}

 private final FileCanonicalIdentityStateRepository states;
 private final InMemoryExternalAdBindingRegistry registry;
 private final InMemoryExternalAdBindingRegistry.Policy policy;
 private final Oi015Verifier verifier;

 public AdSimulatorApplication(FileCanonicalIdentityStateRepository states,InMemoryExternalAdBindingRegistry registry,InMemoryExternalAdBindingRegistry.Policy policy,Oi015Verifier verifier){
  this.states=states;this.registry=registry;this.policy=policy;this.verifier=verifier;
 }

 public static void main(String[] a){SpringApplication.run(AdSimulatorApplication.class,a);}

 @Bean static FileCanonicalIdentityStateRepository states(){return new FileCanonicalIdentityStateRepository(Path.of(env("OPENIDENTITY_STATE_DIR","../../dev/openidentity-state")));}
 @Bean static InMemoryExternalAdBindingRegistry registry(){return new InMemoryExternalAdBindingRegistry(Path.of(env("OPENIDENTITY_AD_BINDING_STORE","../../dev/openidentity-ad-bindings.store")));}
 @Bean static InMemoryExternalAdBindingRegistry.Policy policy(FileCanonicalIdentityStateRepository states){return new InMemoryExternalAdBindingRegistry.Policy(){
  public boolean directoryTrusted(byte[] d){return Arrays.equals(d,dir());}
  public boolean serviceAllowed(byte[] d,String s){return "openidentity-ad-link-service".equals(s);}
  public boolean mechanismAllowed(byte[] d,int m){return m==ExternalAdBindingV1.KERBEROS_SPNEGO;}
  public boolean identityActive(byte[] id){var s=states.resolve(id);return s!=null&&s.active();}
  public long currentAuthenticationGeneration(byte[] id){var s=states.resolve(id);if(s==null)throw new IllegalArgumentException("identity");return s.authenticationAuthority().generation();}
 };}
 @Bean static Oi015Verifier verifier(FileCanonicalIdentityStateRepository states){return new Oi015Verifier(new CanonicalAuthenticationStateResolver(states),300);}

 @GetMapping("/") Map<String,Object> home(HttpSession s){
  var r=(InMemoryExternalAdBindingRegistry.Resolved)s.getAttribute(RESOLVED);
  if(r!=null)return Map.of("status","AUTHENTICATED","provider","AD_SIMULATOR","productionAuthentication",false,"identity",hex(r.identity()),"bindingStatus","ACTIVE");
  return Map.of("status","UNBOUND","provider","AD_SIMULATOR","productionAuthentication",false,"login","/simulator/login");
 }

 @GetMapping("/simulator/login") Map<String,Object> login(HttpSession s){
  var resolver=new DeterministicAdPrincipalResolver(List.of(new DeterministicAdPrincipalResolver.Entry("lab","alice@OI-TEST.INTERNAL",dir(),guid(),true,true,Map.of("displayName","Alice Test"))));
  var v=resolver.resolve(new AdAuthenticationEvidence("lab","alice@OI-TEST.INTERNAL","openidentity-ad-link-service",ExternalAdBindingV1.KERBEROS_SPNEGO,true,Map.of("simulated",true)));
  s.setAttribute(AD,v);
  try{
   var r=registry.resolve(ExternalAdPrincipalBridge.registryPrincipal(v),System.currentTimeMillis()/1000,policy);s.setAttribute(RESOLVED,r);
   return Map.of("status","RESOLVED","provider","AD_SIMULATOR","productionAuthentication",false,"identity",hex(r.identity()));
  }catch(ExternalAdBindingException e){
   if(e.error()!=ExternalAdBindingError.BINDING_NOT_FOUND)throw e;
   return Map.of("status","SIMULATED_AD_AUTHENTICATED","provider","AD_SIMULATOR","productionAuthentication",false,"authenticatedPrincipal","alice@OI-TEST.INTERNAL","authenticationMechanism","SIMULATED_KERBEROS_SPNEGO","next","GET /openidentity/link/begin?identity=<64-hex OpenIdentity ID>");
  }
 }

 @GetMapping("/openidentity/link/begin") Map<String,String> begin(@RequestParam("identity")String identity,HttpSession s){
  var v=(VerifiedAdPrincipal)s.getAttribute(AD);if(v==null)throw new IllegalStateException("simulated AD login required");
  byte[] id=HexFormat.of().parseHex(identity);if(id.length!=32)throw new IllegalArgumentException("identity");
  var canonical=states.resolve(id);if(canonical==null)throw new IllegalArgumentException("identity not found");
  long now=System.currentTimeMillis()/1000,gen=policy.currentAuthenticationGeneration(id);
  var b=new ExternalAdBindingV1.Binding(id,v.directoryId(),v.objectGuid(),v.serviceId(),now,null,gen);
  byte[] challenge=random(32),aud=random(32),nonce=random(32),ctx=ExternalAdBindingV1.encodeContext(ExternalAdBindingV1.BIND,b,v.authenticationMechanism(),challenge,null),hash=ExternalAdBindingV1.contextHash(ctx);
  s.setAttribute(PENDING,new Pending(v,b,challenge,aud,nonce,hash));
  return Map.of("purpose","openidentity.external-ad.bind","contextHashHex",hex(hash),"audienceHex",hex(aud),"nonceHex",hex(nonce),"stateHashHex",hex(canonical.stateHash()),"authenticationGeneration",Long.toString(gen));
 }

 @PostMapping(value="/openidentity/link/complete",consumes="text/plain") Map<String,Object> complete(@RequestBody String securedHex,HttpSession s){
  var p=(Pending)s.getAttribute(PENDING);if(p==null)throw new IllegalStateException("No pending AD binding ceremony");
  var secured=Oi015Codec.decode(HexFormat.of().parseHex(securedHex.trim()));
  var vr=verifier.tryVerify(secured,p.audience(),"openidentity.external-ad.bind",p.nonce(),p.contextHash(),System.currentTimeMillis()/1000);
  if(!vr.valid())throw new ExternalAdBindingException(vr.contextMismatch()?ExternalAdBindingError.BINDING_CONTEXT_MISMATCH:ExternalAdBindingError.BINDING_AUTHORIZATION_INVALID);
  var principal=ExternalAdPrincipalBridge.registryPrincipal(p.principal());
  var state=registry.bind(principal,p.binding().identity(),p.binding().createdAt(),p.binding().expiresAt(),p.challenge(),new InMemoryExternalAdBindingRegistry.Authorization(true,"openidentity.external-ad.bind",true,false),policy);
  var resolved=registry.resolve(principal,System.currentTimeMillis()/1000,policy);
  s.setAttribute(RESOLVED,resolved);s.removeAttribute(PENDING);
  return Map.of("status","BOUND","provider","AD_SIMULATOR","productionAuthentication",false,"identity",hex(resolved.identity()),"bindingId",hex(state.bindingId()),"next","/");
 }

 static byte[] dir(){return HexFormat.of().parseHex("d0d1d2d3d4d5d6d7d8d9dadbdcdddedf");}
 static byte[] guid(){return HexFormat.of().parseHex("00112233445566778899aabbccddeeff");}
 static byte[] random(int n){byte[] b=new byte[n];new SecureRandom().nextBytes(b);return b;}
 static String hex(byte[] b){return HexFormat.of().formatHex(b);}
 static String env(String n,String d){String v=System.getenv(n);return v==null||v.isBlank()?d:v;}
}
