package org.openidentity.spring.auth;
import jakarta.servlet.http.*;import org.springframework.http.*;import org.springframework.security.core.context.*;import org.springframework.security.web.context.HttpSessionSecurityContextRepository;import org.springframework.web.bind.annotation.*;import java.security.SecureRandom;import java.util.*;
@RestController
@RequestMapping("/openidentity/auth/transaction")
public final class OpenIdentityAuthenticatorTransactionController {
 private final OpenIdentityAuthenticationService service;private final OpenIdentityAuthenticationTransactionStore store;private final SecureRandom random=new SecureRandom();
 public OpenIdentityAuthenticatorTransactionController(OpenIdentityAuthenticationService service,OpenIdentityAuthenticationTransactionStore store){this.service=service;this.store=store;}
 @PostMapping public Map<String,Object> create(@RequestBody CreateRequest r){
  if(!valid(r.requestTarget()))throw new IllegalArgumentException("requestTarget");var issued=service.issue(OpenIdentityAuthenticationContext.oauthAuthorizationContext(r.requestTarget()));String tx=randomId();var c=issued.challenge();var h=HexFormat.of();
  String challenge="{\"challengeId\":\""+issued.challengeId()+"\",\"audienceHex\":\""+h.formatHex(c.audience())+"\",\"purpose\":\""+c.purpose()+"\",\"nonceHex\":\""+h.formatHex(c.nonce())+"\",\"contextHashHex\":\""+h.formatHex(c.contextHash())+"\",\"issuedAt\":"+c.issuedAt()+",\"expiresAt\":"+c.expiresAt()+"}";
  store.put(tx,new OpenIdentityAuthenticationTransactionStore.Transaction(issued.challengeId(),r.requestTarget(),challenge,OpenIdentityAuthenticationTransactionStore.Transaction.State.PENDING,null));
  return Map.of("transactionId",tx,"authenticatorUri","org.openidentity.auth:/authenticate?transaction="+tx,"expiresAt",c.expiresAt());
 }
 @GetMapping("/{id}/challenge") public ResponseEntity<String> challenge(@PathVariable String id){var t=store.get(id);return t==null?ResponseEntity.notFound().build():ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(t.challengeJson());}
 @PostMapping("/{id}/assertion") public ResponseEntity<Map<String,Object>> assertion(@PathVariable String id,@RequestBody AssertionRequest r){
  var t=store.get(id);if(t==null||t.state()!=OpenIdentityAuthenticationTransactionStore.Transaction.State.PENDING)return ResponseEntity.status(409).body(Map.of("status","REJECTED"));
  try{var a=service.verify(t.challengeId(),Base64.getUrlDecoder().decode(r.assertionBase64Url()));store.authenticated(id,a);return ResponseEntity.ok(Map.of("status","AUTHENTICATED","identity",a.openIdentityIdHex()));}catch(RuntimeException e){store.rejected(id);return ResponseEntity.status(401).body(Map.of("status","REJECTED"));}
 }
 @PostMapping("/{id}/complete") public ResponseEntity<Map<String,Object>> complete(@PathVariable String id,HttpServletRequest req,HttpServletResponse res){
  var t=store.consume(id);if(t==null||t.state()!=OpenIdentityAuthenticationTransactionStore.Transaction.State.AUTHENTICATED)return ResponseEntity.status(409).body(Map.of("status",t==null?"UNKNOWN":t.state().name()));
  var ctx=SecurityContextHolder.createEmptyContext();ctx.setAuthentication(t.authentication());SecurityContextHolder.setContext(ctx);new HttpSessionSecurityContextRepository().saveContext(ctx,req,res);return ResponseEntity.ok(Map.of("status","AUTHENTICATED","continue",t.requestTarget()));
 }
 @GetMapping("/{id}") public ResponseEntity<Map<String,Object>> status(@PathVariable String id){var t=store.get(id);return t==null?ResponseEntity.notFound().build():ResponseEntity.ok(Map.of("status",t.state().name()));}
 private String randomId(){byte[] b=new byte[32];random.nextBytes(b);return Base64.getUrlEncoder().withoutPadding().encodeToString(b);}
 private static boolean valid(String t){return t!=null&&t.startsWith("/oauth2/authorize?")&&!t.startsWith("//")&&t.indexOf(13)<0&&t.indexOf(10)<0;}
 public record CreateRequest(String requestTarget){}public record AssertionRequest(String assertionBase64Url){}
}