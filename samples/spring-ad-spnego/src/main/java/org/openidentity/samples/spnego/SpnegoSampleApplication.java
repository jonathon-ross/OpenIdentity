package org.openidentity.samples.spnego;
import org.openidentity.ad.spnego.SpnegoAcceptor;import org.springframework.boot.*;import org.springframework.boot.autoconfigure.SpringBootApplication;import org.springframework.context.annotation.Bean;import org.springframework.http.*;import org.springframework.web.bind.annotation.*;import java.nio.file.*;import java.util.*;

@SpringBootApplication @RestController
public class SpnegoSampleApplication {
 private final SpnegoAcceptor acceptor;
 public SpnegoSampleApplication(SpnegoAcceptor acceptor){this.acceptor=acceptor;}
 public static void main(String[] a){SpringApplication.run(SpnegoSampleApplication.class,a);}
 @Bean static SpnegoAcceptor acceptor(){
  String principal=req("OPENIDENTITY_KERBEROS_SERVICE_PRINCIPAL");
  Path keytab=Path.of(req("OPENIDENTITY_KERBEROS_KEYTAB"));
  return new SpnegoAcceptor(principal,keytab);
 }
 @GetMapping("/") ResponseEntity<?> home(@RequestHeader(value="Authorization",required=false)String authorization){
  if(authorization==null||!authorization.regionMatches(true,0,"Negotiate ",0,10))return challenge(null);
  byte[] token;try{token=Base64.getDecoder().decode(authorization.substring(10).trim());}catch(IllegalArgumentException e){return ResponseEntity.badRequest().body(Map.of("status","INVALID_NEGOTIATE_TOKEN"));}
  SpnegoAcceptor.Result r;
  try{r=acceptor.accept(token);}catch(IllegalArgumentException e){return challenge(null);}
  if(!r.established())return challenge(r.responseToken());
  HttpHeaders h=new HttpHeaders();if(r.responseToken().length>0)h.set(HttpHeaders.WWW_AUTHENTICATE,"Negotiate "+Base64.getEncoder().encodeToString(r.responseToken()));
  return new ResponseEntity<>(Map.of("status","KERBEROS_AUTHENTICATED","principal",r.principal(),"productionAuthentication",true,"authenticationMechanism","KERBEROS_SPNEGO"),h,HttpStatus.OK);
 }
 private static ResponseEntity<Map<String,Object>> challenge(byte[] response){
  HttpHeaders h=new HttpHeaders();String v="Negotiate";if(response!=null&&response.length>0)v+=" "+Base64.getEncoder().encodeToString(response);h.set(HttpHeaders.WWW_AUTHENTICATE,v);
  return new ResponseEntity<>(Map.of("status","NEGOTIATE_REQUIRED"),h,HttpStatus.UNAUTHORIZED);
 }
 private static String req(String n){String v=System.getenv(n);if(v==null||v.isBlank())throw new IllegalStateException("missing environment variable "+n);return v;}
}