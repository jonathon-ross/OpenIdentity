package org.openidentity.samples.entra;

import org.openidentity.oidc.*;
import org.openidentity.spring.oidc.*;
import org.openidentity.spring.oidc.entra.*;
import org.springframework.boot.*;import org.springframework.boot.autoconfigure.SpringBootApplication;import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;import org.springframework.security.oauth2.client.registration.*;import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@SpringBootApplication
@RestController
public class EntraOidcSampleApplication {
 public static void main(String[] args){SpringApplication.run(EntraOidcSampleApplication.class,args);}
 @Bean EntraOidcProfile entraProfile(){return new EntraOidcProfile(required("OPENIDENTITY_ENTRA_TENANT_ID"),Set.of(required("OPENIDENTITY_ENTRA_CLIENT_ID")));}
 @Bean ClientRegistrationRepository registrations(EntraOidcProfile p){return new InMemoryClientRegistrationRepository(EntraClientRegistrationFactory.create("entra",p.tenantId(),required("OPENIDENTITY_ENTRA_CLIENT_ID"),required("OPENIDENTITY_ENTRA_CLIENT_SECRET")));}
 @Bean InMemoryExternalOidcBindingRegistry registry(){return new InMemoryExternalOidcBindingRegistry();}
 @Bean InMemoryExternalOidcBindingRegistry.Policy bindingPolicy(EntraOidcProfile p){return new EntraExternalOidcBindingPolicy(p,id->true,id->1L,principal->true);}
 @Bean SpringExternalOidcAuthenticationResolver resolver(InMemoryExternalOidcBindingRegistry r,InMemoryExternalOidcBindingRegistry.Policy p){return new SpringExternalOidcAuthenticationResolver(new SpringOidcPrincipalMapper(),r,p);}
 @Bean SecurityFilterChain security(HttpSecurity http,ClientRegistrationRepository regs,SpringExternalOidcAuthenticationResolver resolver)throws Exception{
  http.authorizeHttpRequests(a->a.requestMatchers("/","/openidentity/link").permitAll().anyRequest().authenticated()).oauth2Login(o->o.successHandler(new OpenIdentityOidcLoginSuccessHandler(regs,resolver)));return http.build();
 }
 @GetMapping("/") String home(){return "OpenIdentity Entra OIDC sample";}
 @GetMapping("/openidentity/link") String link(){return "Entra login succeeded, but this external identity is not yet bound to an OpenIdentity identity.";}
 private static String required(String n){String v=System.getenv(n);if(v==null||v.isBlank())throw new IllegalStateException("Missing environment variable "+n);return v;}
}
