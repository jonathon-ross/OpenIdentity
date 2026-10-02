package org.openidentity.samples.oidcclient;
import org.springframework.boot.*;import org.springframework.boot.autoconfigure.SpringBootApplication;import org.springframework.security.config.annotation.web.builders.HttpSecurity;import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;import org.springframework.security.oauth2.core.oidc.user.OidcUser;import org.springframework.security.web.SecurityFilterChain;import org.slf4j.*;import org.springframework.context.annotation.Bean;import org.springframework.web.bind.annotation.*;import jakarta.servlet.*;import jakarta.servlet.http.*;import org.springframework.web.filter.OncePerRequestFilter;import java.io.IOException;import java.util.*;
@SpringBootApplication @RestController
public class OidcClientReferenceApplication {
 private static final Logger LOG=LoggerFactory.getLogger(OidcClientReferenceApplication.class);
 public static void main(String[] a){SpringApplication.run(OidcClientReferenceApplication.class,a);}
 @Bean SecurityFilterChain security(HttpSecurity http)throws Exception{return http.authorizeHttpRequests(a->a.requestMatchers("/","/error").permitAll().anyRequest().authenticated()).oauth2Login(o->o
  .successHandler((req,res,auth)->{LOG.info("OIDC LOGIN SUCCESS principal={}",auth.getName());res.sendRedirect("/me");})
  .failureHandler((req,res,e)->{LOG.error("OIDC LOGIN FAILURE type={} message={}",e.getClass().getName(),e.getMessage(),e);res.sendError(401,"OIDC login failed: "+e.getMessage());})
 ).build();}
 @GetMapping("/") Map<String,String> home(){return Map.of("login","/oauth2/authorization/openidentity");}
 @Bean OncePerRequestFilter errorDiagnostics(){return new OncePerRequestFilter(){
   @Override protected boolean shouldNotFilterErrorDispatch(){return false;}
   @Override protected boolean shouldNotFilter(HttpServletRequest req){return req.getDispatcherType()!=DispatcherType.ERROR;}
   @Override protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain)throws ServletException,IOException{
    Object ex=req.getAttribute("jakarta.servlet.error.exception");Object status=req.getAttribute("jakarta.servlet.error.status_code");Object uri=req.getAttribute("jakarta.servlet.error.request_uri");
    LOG.error("CLIENT ERROR status={} uri={} exceptionType={} message={}",status,uri,ex==null?null:ex.getClass().getName(),ex instanceof Throwable t?t.getMessage():null);
    chain.doFilter(req,res);
   }
  };}
 @GetMapping("/me") Map<String,Object> me(OAuth2AuthenticationToken authentication){
  OidcUser user=(OidcUser)authentication.getPrincipal();
  return Map.of("subject",user.getSubject(),"issuer",String.valueOf(user.getIssuer()),"claims",user.getClaims());
 }
}