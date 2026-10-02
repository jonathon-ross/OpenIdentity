package org.openidentity.samples.microsoftad;
import jakarta.servlet.http.HttpSession;import org.openidentity.ad.*;import org.openidentity.ad.ldap.*;import org.openidentity.ad.spnego.*;import org.springframework.boot.*;import org.springframework.boot.autoconfigure.SpringBootApplication;import org.springframework.context.annotation.Bean;import org.springframework.http.*;import org.springframework.web.bind.annotation.*;import java.nio.file.*;import java.util.*;

@SpringBootApplication @RestController
public class MicrosoftAdApplication {
 private final SpnegoAcceptor spnego;private final AdPrincipalResolver ldap;
 public MicrosoftAdApplication(SpnegoAcceptor spnego,AdPrincipalResolver ldap){this.spnego=spnego;this.ldap=ldap;}
 public static void main(String[] a){SpringApplication.run(MicrosoftAdApplication.class,a);}
 @Bean static SpnegoAcceptor spnego(){return new SpnegoAcceptor(req("OPENIDENTITY_KERBEROS_SERVICE_PRINCIPAL"),Path.of(req("OPENIDENTITY_KERBEROS_KEYTAB")));}
 @Bean static AdPrincipalResolver ldap(){String password=req("OPENIDENTITY_LDAP_BIND_PASSWORD");return new LdapAdPrincipalResolver(new LdapAdPrincipalResolver.Profile("microsoft-ad",env("OPENIDENTITY_AD_HOST","DC01.oi-test.internal"),636,env("OPENIDENTITY_AD_BASE_DN","DC=oi-test,DC=internal"),env("OPENIDENTITY_AD_BIND_DN","oi-ldap@oi-test.internal"),password,HexFormat.of().parseHex(env("OPENIDENTITY_AD_DIRECTORY_ID","d0d1d2d3d4d5d6d7d8d9dadbdcdddedf")),true));}
 @GetMapping("/") ResponseEntity<?> home(@RequestHeader(value="Authorization",required=false)String authorization,HttpSession session){
  if(authorization==null||!authorization.regionMatches(true,0,"Negotiate ",0,10))return challenge(null);
  byte[] token;try{token=Base64.getDecoder().decode(authorization.substring(10).trim());}catch(IllegalArgumentException e){return ResponseEntity.badRequest().body(Map.of("status","INVALID_NEGOTIATE_TOKEN"));}
  SpnegoAcceptor.Exchange exchange=(SpnegoAcceptor.Exchange)session.getAttribute("SPNEGO_EXCHANGE");if(exchange==null){exchange=spnego.begin();session.setAttribute("SPNEGO_EXCHANGE",exchange);}
  SpnegoAcceptor.Result gss;try{gss=exchange.accept(token);}catch(IllegalArgumentException e){exchange.close();session.removeAttribute("SPNEGO_EXCHANGE");return challenge(null);}
  if(!gss.established())return challenge(gss.responseToken());
  exchange.close();session.removeAttribute("SPNEGO_EXCHANGE");
  String principal=gss.principal();var evidence=new AdAuthenticationEvidence("microsoft-ad",principal,"openidentity-ad-link-service",ExternalAdBindingV1.KERBEROS_SPNEGO,true,Map.of("gssEstablished",true));
  VerifiedAdPrincipal verified=ldap.resolve(evidence);
  HttpHeaders h=new HttpHeaders();if(gss.responseToken().length>0)h.set(HttpHeaders.WWW_AUTHENTICATE,"Negotiate "+Base64.getEncoder().encodeToString(gss.responseToken()));
  return new ResponseEntity<>(Map.of("status","MICROSOFT_AD_AUTHENTICATED","provider","MICROSOFT_ACTIVE_DIRECTORY","principal",principal,"authentication","KERBEROS_SPNEGO","productionAuthentication",true,"principalResolution","LDAPS","objectGuidLdapOctetsHex",HexFormat.of().formatHex(verified.objectGuid()),"directoryIdHex",HexFormat.of().formatHex(verified.directoryId()),"accountUsable",verified.accountUsable()),h,HttpStatus.OK);
 }
 private static ResponseEntity<Map<String,Object>> challenge(byte[] response){HttpHeaders h=new HttpHeaders();String v="Negotiate";if(response!=null&&response.length>0)v+=" "+Base64.getEncoder().encodeToString(response);h.set(HttpHeaders.WWW_AUTHENTICATE,v);return new ResponseEntity<>(Map.of("status","NEGOTIATE_REQUIRED"),h,HttpStatus.UNAUTHORIZED);}
 private static String req(String n){String v=System.getenv(n);if(v==null||v.isBlank())throw new IllegalStateException("missing environment variable "+n);return v;}
 private static String env(String n,String d){String v=System.getenv(n);return v==null||v.isBlank()?d:v;}
}