package org.openidentity.spring.auth;
import jakarta.servlet.http.*;import org.springframework.http.*;import org.springframework.security.core.context.*;import org.springframework.security.web.context.HttpSessionSecurityContextRepository;import org.springframework.web.bind.annotation.*;import java.util.*;
@RestController
@RequestMapping("/openidentity/auth")
public final class OpenIdentityAuthenticationHttpController {
 private final OpenIdentityAuthenticationService service;
 public OpenIdentityAuthenticationHttpController(OpenIdentityAuthenticationService service){this.service=Objects.requireNonNull(service);}
 @PostMapping("/challenge") public Map<String,Object> challenge(@RequestBody ChallengeRequest request){
  byte[] context=OpenIdentityAuthenticationContext.oauthAuthorizationContext(request.requestTarget());var x=service.issue(context);var c=x.challenge();var h=HexFormat.of();
  return Map.of("challengeId",x.challengeId(),"audienceHex",h.formatHex(c.audience()),"purpose",c.purpose(),"nonceHex",h.formatHex(c.nonce()),"contextHashHex",h.formatHex(c.contextHash()),"issuedAt",c.issuedAt(),"expiresAt",c.expiresAt());
 }
 @PostMapping("/verify") public ResponseEntity<Map<String,Object>> verify(@RequestBody VerifyRequest request,HttpServletRequest servletRequest){
  try{
   byte[] bytes=Base64.getUrlDecoder().decode(request.assertionBase64Url());var authentication=service.verify(request.challengeId(),bytes);
   SecurityContext context=SecurityContextHolder.createEmptyContext();context.setAuthentication(authentication);SecurityContextHolder.setContext(context);
   new HttpSessionSecurityContextRepository().saveContext(context,servletRequest,new NoOpResponse());
   return ResponseEntity.ok(Map.of("status","AUTHENTICATED","identity",authentication.openIdentityIdHex()));
  }catch(RuntimeException e){return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("status","REJECTED"));}
 }
 public record ChallengeRequest(String requestTarget){}
 public record VerifyRequest(String challengeId,String assertionBase64Url){}
 private static final class NoOpResponse extends jakarta.servlet.http.HttpServletResponseWrapper {NoOpResponse(){super(new org.springframework.mock.web.MockHttpServletResponse());}}
}