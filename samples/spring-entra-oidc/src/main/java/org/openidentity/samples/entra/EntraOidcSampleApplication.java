package org.openidentity.samples.entra;

import jakarta.servlet.http.HttpSession;
import org.openidentity.auth.*;
import org.openidentity.core.*;
import org.openidentity.oidc.*;
import org.openidentity.spring.oidc.*;
import org.openidentity.spring.oidc.entra.*;
import org.springframework.boot.*;import org.springframework.boot.autoconfigure.SpringBootApplication;import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;import org.springframework.security.oauth2.client.registration.*;import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.*;
import java.nio.file.*;import java.util.*;

@SpringBootApplication @RestController
public class EntraOidcSampleApplication {
 private ExternalOidcBindingHttpSession bindingHttp;
 private ExternalOidcBindingCeremony bindingCeremony;
 private InMemoryExternalOidcBindingRegistry bindingRegistry;
 private InMemoryExternalOidcBindingRegistry.Policy externalBindingPolicy;
 public static void main(String[] args){SpringApplication.run(EntraOidcSampleApplication.class,args);}
 @Bean EntraOidcProfile entraProfile(){return new EntraOidcProfile(required("OPENIDENTITY_ENTRA_TENANT_ID"),Set.of(required("OPENIDENTITY_ENTRA_CLIENT_ID")));}
 @Bean ClientRegistrationRepository registrations(EntraOidcProfile p){return new InMemoryClientRegistrationRepository(EntraClientRegistrationFactory.create("entra",p.tenantId(),required("OPENIDENTITY_ENTRA_CLIENT_ID"),required("OPENIDENTITY_ENTRA_CLIENT_SECRET")));}
 @Bean FileCanonicalIdentityStateRepository canonicalStates(){return new FileCanonicalIdentityStateRepository(Path.of(env("OPENIDENTITY_STATE_DIR","../../dev/openidentity-state")));}
 @Bean InMemoryExternalOidcBindingRegistry registry(){return this.bindingRegistry=new InMemoryExternalOidcBindingRegistry(Path.of(env("OPENIDENTITY_BINDING_STORE","../../dev/openidentity-bindings.store")));}
 @Bean InMemoryExternalOidcBindingRegistry.Policy bindingPolicy(EntraOidcProfile p,FileCanonicalIdentityStateRepository states){return this.externalBindingPolicy=new EntraExternalOidcBindingPolicy(p,id->{var s=states.resolve(id);return s!=null&&s.active();},id->{var s=states.resolve(id);if(s==null)throw new IllegalArgumentException("identity");return s.authenticationAuthority().generation();},principal->true);}
 @Bean SpringExternalOidcAuthenticationResolver resolver(InMemoryExternalOidcBindingRegistry r,InMemoryExternalOidcBindingRegistry.Policy p){return new SpringExternalOidcAuthenticationResolver(new SpringOidcPrincipalMapper(),r,p);}
 @Bean ExternalOidcBindingCeremony ceremony(FileCanonicalIdentityStateRepository states,InMemoryExternalOidcBindingRegistry r,InMemoryExternalOidcBindingRegistry.Policy p){return new ExternalOidcBindingCeremony(new Oi015Verifier(new CanonicalAuthenticationStateResolver(states),300),r,p);}
 @Bean ExternalOidcBindingHttpSession bindingHttp(ClientRegistrationRepository registrations,ExternalOidcBindingCeremony ceremony){this.bindingCeremony=ceremony;return this.bindingHttp=new ExternalOidcBindingHttpSession(new SpringOidcPrincipalMapper(),registrations,ceremony);}
 @Bean SecurityFilterChain security(HttpSecurity http,ClientRegistrationRepository regs,SpringExternalOidcAuthenticationResolver resolver)throws Exception{
  http.authorizeHttpRequests(a->a.requestMatchers("/").permitAll().anyRequest().authenticated()).csrf(c->c.ignoringRequestMatchers("/openidentity/link/complete")).oauth2Login(o->o.successHandler(new OpenIdentityOidcLoginSuccessHandler(regs,resolver)));return http.build();
 }
 @GetMapping("/") Map<String,String> home(HttpSession session){
  Object value=session.getAttribute(OpenIdentityOidcLoginSuccessHandler.SESSION_ATTRIBUTE);
  if(!(value instanceof ResolvedExternalOidcAuthentication resolved))return Map.of("status","UNAUTHENTICATED","login","/oauth2/authorization/entra");
  return Map.of("status","AUTHENTICATED","authentication","OPENIDENTITY_EXTERNAL_OIDC","identity",HexFormat.of().formatHex(resolved.identity()),"provider","Microsoft Entra ID","bindingStatus","ACTIVE");
 }
 @GetMapping("/openidentity/link") Map<String,String> link(){return Map.of("status","Entra authenticated; external identity is not yet bound.","next","GET /openidentity/link/begin?identity=<64-hex OpenIdentity ID>");}
 @GetMapping("/openidentity/identities") Map<String,Object> identities(){Path dir=Path.of(env("OPENIDENTITY_STATE_DIR","../../dev/openidentity-state")).toAbsolutePath().normalize();List<String> ids=new ArrayList<>();try{if(Files.isDirectory(dir))try(var stream=Files.list(dir)){stream.map(p->p.getFileName().toString()).filter(n->n.matches("[0-9a-fA-F]{64}\\.oidstate")).map(n->n.substring(0,64)).sorted().forEach(ids::add);}}catch(java.io.IOException e){throw new java.io.UncheckedIOException(e);}return Map.of("stateDirectory",dir.toString(),"identities",ids);}
 @GetMapping("/openidentity/link/begin") ExternalOidcBindingHttpSession.Request begin(@RequestParam("identity") String identity,OAuth2AuthenticationToken authentication,HttpSession session){
  try{
   byte[] id=hex(identity,32);Path dir=Path.of(env("OPENIDENTITY_STATE_DIR","../../dev/openidentity-state")).toAbsolutePath().normalize();if(!Files.isRegularFile(dir.resolve(identity.toLowerCase(Locale.ROOT)+".oidstate")))throw new IllegalArgumentException("OpenIdentity identity not found in "+dir);
   if(authentication==null)throw new IllegalStateException("No OAuth2AuthenticationToken is present after Entra login");
   return bindingHttp.begin(session,authentication,id,System.currentTimeMillis()/1000,null);
  }catch(RuntimeException e){StringBuilder m=new StringBuilder(e.getClass().getName()).append(": ").append(e.getMessage());for(Throwable x=e.getCause();x!=null;x=x.getCause())m.append(" | CAUSED BY ").append(x.getClass().getName()).append(": ").append(x.getMessage());throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST,m.toString(),e);}
 }
 @PostMapping(value="/openidentity/link/complete",consumes="text/plain") Map<String,String> complete(@RequestBody String securedHex,HttpSession session){
  var pending=bindingHttp.pending(session);if(pending==null)throw new IllegalStateException("No pending binding ceremony");
  byte[] secured=HexFormat.of().parseHex(securedHex.trim());bindingCeremony.complete(pending.pending(),Oi015Codec.decode(secured),pending.audience(),pending.nonce(),System.currentTimeMillis()/1000);bindingHttp.clear(session);
  var p=pending.pending().principal();var resolved=bindingRegistry.resolve(p,System.currentTimeMillis()/1000,externalBindingPolicy);session.setAttribute(OpenIdentityOidcLoginSuccessHandler.SESSION_ATTRIBUTE,resolved);
  return Map.of("status","BOUND","identity",HexFormat.of().formatHex(resolved.identity()),"next","/");
 }
 private static byte[] hex(String s,int n){byte[] b=HexFormat.of().parseHex(s);if(b.length!=n)throw new IllegalArgumentException("expected "+n+" bytes");return b;}
 private static String required(String n){String v=System.getenv(n);if(v==null||v.isBlank())throw new IllegalStateException("Missing environment variable "+n);return v;}
 private static String env(String n,String d){String v=System.getenv(n);return v==null||v.isBlank()?d:v;}
}
