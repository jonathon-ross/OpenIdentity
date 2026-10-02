package org.openidentity.samples.adreference;
import org.openidentity.spring.ad.*;import org.springframework.boot.*;import org.springframework.boot.autoconfigure.SpringBootApplication;import org.springframework.security.core.Authentication;import org.springframework.web.bind.annotation.*;import java.util.*;
@SpringBootApplication @RestController
public class ActiveDirectoryReferenceApplication {
 public static void main(String[] args){SpringApplication.run(ActiveDirectoryReferenceApplication.class,args);}
 @GetMapping("/whoami") Map<String,Object> whoami(Authentication authentication){
  var token=(OpenIdentityAdAuthenticationToken)authentication;var r=token.result();Map<String,Object> out=new LinkedHashMap<>();out.put("kerberosPrincipal",r.kerberosPrincipal());out.put("bindingStatus",r.bindingStatus().name());out.put("bound",r.bound());if(r.bound())out.put("openIdentityId",HexFormat.of().formatHex(r.openIdentityId()));out.put("authorities",token.getAuthorities().stream().map(a->a.getAuthority()).toList());return out;
 }
 @GetMapping("/api/identity") Map<String,Object> identity(Authentication authentication){return Map.of("principal",authentication.getPrincipal(),"status","OPENIDENTITY_AUTHORIZED");}
}