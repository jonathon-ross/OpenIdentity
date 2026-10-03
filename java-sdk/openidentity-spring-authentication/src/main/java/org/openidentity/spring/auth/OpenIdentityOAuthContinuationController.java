package org.openidentity.spring.auth;
import jakarta.servlet.http.HttpServletRequest;import jakarta.servlet.http.HttpServletResponse;import org.springframework.http.HttpStatus;import org.springframework.http.ResponseEntity;import org.springframework.security.core.context.SecurityContextHolder;import org.springframework.security.web.context.HttpSessionSecurityContextRepository;import org.springframework.web.bind.annotation.*;import java.util.*;
@RestController
@RequestMapping("/openidentity/auth/login")
public final class OpenIdentityOAuthContinuationController {
 private final OpenIdentityAuthenticationService service;private final OpenIdentityAuthenticationContinuationStore continuations;
 public OpenIdentityOAuthContinuationController(OpenIdentityAuthenticationService service,OpenIdentityAuthenticationContinuationStore continuations){this.service=Objects.requireNonNull(service);this.continuations=Objects.requireNonNull(continuations);}
 @PostMapping("/challenge") public Map<String,Object> challenge(@RequestBody ChallengeRequest request){
  String target=request.requestTarget();if(!validTarget(target))throw new IllegalArgumentException("requestTarget");var x=service.issue(OpenIdentityAuthenticationContext.oauthAuthorizationContext(target));continuations.put(x.challengeId(),target);var c=x.challenge();var h=HexFormat.of();
  return Map.of("challengeId",x.challengeId(),"audienceHex",h.formatHex(c.audience()),"purpose",c.purpose(),"nonceHex",h.formatHex(c.nonce()),"contextHashHex",h.formatHex(c.contextHash()),"issuedAt",c.issuedAt(),"expiresAt",c.expiresAt());
 }
 @PostMapping("/verify") public ResponseEntity<Map<String,Object>> verify(@RequestBody VerifyRequest request,HttpServletRequest req,HttpServletResponse res){
  try{
   byte[] bytes=Base64.getUrlDecoder().decode(request.assertionBase64Url());var authentication=service.verify(request.challengeId(),bytes);String target=continuations.consume(request.challengeId());if(target==null)throw new IllegalArgumentException("continuation");
   var context=SecurityContextHolder.createEmptyContext();context.setAuthentication(authentication);SecurityContextHolder.setContext(context);new HttpSessionSecurityContextRepository().saveContext(context,req,res);
   return ResponseEntity.ok(Map.of("status","AUTHENTICATED","identity",authentication.openIdentityIdHex(),"continue",target));
  }catch(RuntimeException e){continuations.consume(request.challengeId());return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("status","REJECTED"));}
 }
 private static boolean validTarget(String t){return t!=null&&t.startsWith("/oauth2/authorize?")&&!t.startsWith("//")&&t.indexOf(13)<0&&t.indexOf(10)<0;}
 public record ChallengeRequest(String requestTarget){}
 public record VerifyRequest(String challengeId,String assertionBase64Url){}
}