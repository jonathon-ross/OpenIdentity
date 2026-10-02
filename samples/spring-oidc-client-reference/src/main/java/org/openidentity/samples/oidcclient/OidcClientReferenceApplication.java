package org.openidentity.samples.oidcclient;
import org.springframework.boot.*;import org.springframework.boot.autoconfigure.SpringBootApplication;import org.springframework.security.config.annotation.web.builders.HttpSecurity;import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;import org.springframework.security.oauth2.core.oidc.user.OidcUser;import org.springframework.security.web.SecurityFilterChain;import org.springframework.context.annotation.Bean;import org.springframework.web.bind.annotation.*;import java.util.*;
@SpringBootApplication @RestController
public class OidcClientReferenceApplication {
 public static void main(String[] a){SpringApplication.run(OidcClientReferenceApplication.class,a);}
 @Bean SecurityFilterChain security(HttpSecurity http)throws Exception{return http.authorizeHttpRequests(a->a.requestMatchers("/").permitAll().anyRequest().authenticated()).oauth2Login(o->{}).build();}
 @GetMapping("/") Map<String,String> home(){return Map.of("login","/oauth2/authorization/openidentity");}
 @GetMapping("/me") Map<String,Object> me(OAuth2AuthenticationToken authentication){
  OidcUser user=(OidcUser)authentication.getPrincipal();
  return Map.of("subject",user.getSubject(),"issuer",String.valueOf(user.getIssuer()),"claims",user.getClaims());
 }
}