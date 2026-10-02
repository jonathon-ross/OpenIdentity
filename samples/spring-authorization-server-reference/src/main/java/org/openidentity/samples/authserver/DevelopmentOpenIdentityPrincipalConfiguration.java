package org.openidentity.samples.authserver;
import jakarta.servlet.*;import jakarta.servlet.http.*;import org.openidentity.spring.OpenIdentityPrincipal;import org.springframework.context.annotation.*;import org.springframework.security.authentication.AbstractAuthenticationToken;import org.springframework.security.core.authority.SimpleGrantedAuthority;import org.springframework.security.core.context.SecurityContextHolder;import org.springframework.web.filter.OncePerRequestFilter;import java.io.*;import java.util.*;
@Configuration @Profile("dev-openidentity-principal")
public class DevelopmentOpenIdentityPrincipalConfiguration {
 @Bean OncePerRequestFilter developmentOpenIdentityPrincipalFilter(){return new OncePerRequestFilter(){@Override protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain)throws ServletException,IOException{if(SecurityContextHolder.getContext().getAuthentication()==null){var c=SecurityContextHolder.createEmptyContext();c.setAuthentication(new DevPrincipal());SecurityContextHolder.setContext(c);}chain.doFilter(req,res);}};}
 static final class DevPrincipal extends AbstractAuthenticationToken implements OpenIdentityPrincipal{
  private final byte[] id=HexFormat.of().parseHex("99e2da9324adadb2f18350e1b95d9e491a502f4a91e12857cd7c092c0b0e62f3");
  DevPrincipal(){super(List.of(new SimpleGrantedAuthority("ROLE_OPENIDENTITY")));setAuthenticated(true);}@Override public Object getPrincipal(){return openIdentityIdHex();}@Override public Object getCredentials(){return "";}@Override public byte[] openIdentityId(){return id.clone();}
 }
}