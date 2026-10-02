package org.openidentity.samples.spnego;
import org.openidentity.ad.spnego.SpnegoAcceptor;import jakarta.servlet.http.HttpSession;import org.springframework.boot.*;import org.springframework.boot.autoconfigure.SpringBootApplication;import org.springframework.context.annotation.Bean;import org.springframework.http.*;import org.slf4j.*;import org.springframework.web.bind.annotation.*;import java.nio.file.*;import java.util.*;

@SpringBootApplication @RestController
public class SpnegoSampleApplication {
 private static final Logger LOG=LoggerFactory.getLogger(SpnegoSampleApplication.class);
 private final SpnegoAcceptor acceptor;
 public SpnegoSampleApplication(SpnegoAcceptor acceptor){this.acceptor=acceptor;}
 public static void main(String[] a){SpringApplication.run(SpnegoSampleApplication.class,a);}
 @Bean static SpnegoAcceptor acceptor(){
  String principal=req("OPENIDENTITY_KERBEROS_SERVICE_PRINCIPAL");
  Path keytab=Path.of(req("OPENIDENTITY_KERBEROS_KEYTAB"));
  return new SpnegoAcceptor(principal,keytab);
 }
 @GetMapping("/") ResponseEntity<?> home(@RequestHeader(value="Authorization",required=false)String authorization,HttpSession session){
  if(authorization==null){LOG.info("SPNEGO request: no Authorization header; issuing Negotiate challenge");return challenge(null);}
  if(!authorization.regionMatches(true,0,"Negotiate ",0,10)){LOG.warn("SPNEGO request: unsupported Authorization scheme");return challenge(null);}
  LOG.info("SPNEGO request: Negotiate header present, encoded token chars={}",authorization.length()-10);
  byte[] token;try{token=Base64.getDecoder().decode(authorization.substring(10).trim());}catch(IllegalArgumentException e){return ResponseEntity.badRequest().body(Map.of("status","INVALID_NEGOTIATE_TOKEN"));}
  SpnegoAcceptor.Exchange exchange=(SpnegoAcceptor.Exchange)session.getAttribute("SPNEGO_EXCHANGE");
  if(exchange==null){exchange=acceptor.begin();session.setAttribute("SPNEGO_EXCHANGE",exchange);}
  SpnegoAcceptor.Result r;
  try{r=exchange.accept(token);}catch(IllegalArgumentException e){LOG.warn("SPNEGO verification rejected: {}: {}",e.getClass().getSimpleName(),e.getMessage());Throwable cause=e.getCause();if(cause!=null)LOG.warn("SPNEGO cause: {}: {}",cause.getClass().getName(),cause.getMessage());exchange.close();session.removeAttribute("SPNEGO_EXCHANGE");return challenge(null);}
  if(!r.established()){LOG.info("SPNEGO continuation required; response token bytes={}",r.responseToken().length);return challenge(r.responseToken());}
  LOG.info("SPNEGO established principal={}",r.principal());
  exchange.close();session.removeAttribute("SPNEGO_EXCHANGE");
  HttpHeaders h=new HttpHeaders();if(r.responseToken().length>0)h.set(HttpHeaders.WWW_AUTHENTICATE,"Negotiate "+Base64.getEncoder().encodeToString(r.responseToken()));
  return new ResponseEntity<>(Map.of("status","KERBEROS_AUTHENTICATED","principal",r.principal(),"productionAuthentication",true,"authenticationMechanism","KERBEROS_SPNEGO"),h,HttpStatus.OK);
 }
 private static ResponseEntity<Map<String,Object>> challenge(byte[] response){
  HttpHeaders h=new HttpHeaders();String v="Negotiate";if(response!=null&&response.length>0)v+=" "+Base64.getEncoder().encodeToString(response);h.set(HttpHeaders.WWW_AUTHENTICATE,v);
  return new ResponseEntity<>(Map.of("status","NEGOTIATE_REQUIRED"),h,HttpStatus.UNAUTHORIZED);
 }
 private static String req(String n){String v=System.getenv(n);if(v==null||v.isBlank())throw new IllegalStateException("missing environment variable "+n);return v;}
}