package org.openidentity.spring.ad;
import jakarta.servlet.*;import jakarta.servlet.http.*;import org.openidentity.ad.spnego.SpnegoAcceptor;import org.springframework.http.HttpHeaders;import org.springframework.security.core.context.SecurityContextHolder;import org.springframework.web.filter.OncePerRequestFilter;import java.io.*;import java.util.*;

public final class OpenIdentitySpnegoAuthenticationFilter extends OncePerRequestFilter {
 private static final String EXCHANGE=OpenIdentitySpnegoAuthenticationFilter.class.getName()+".EXCHANGE";
 private final SpnegoExchangeProvider exchanges;private final OpenIdentityActiveDirectoryService service;
 public OpenIdentitySpnegoAuthenticationFilter(SpnegoExchangeProvider exchanges,OpenIdentityActiveDirectoryService service){this.exchanges=Objects.requireNonNull(exchanges);this.service=Objects.requireNonNull(service);}
 @Override protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain)throws ServletException,IOException{
  if(SecurityContextHolder.getContext().getAuthentication()!=null){chain.doFilter(req,res);return;}
  String h=req.getHeader(HttpHeaders.AUTHORIZATION);
  if(h==null||!h.regionMatches(true,0,"Negotiate ",0,10)){challenge(res,null);return;}
  byte[] token;try{token=Base64.getDecoder().decode(h.substring(10).trim());}catch(IllegalArgumentException e){res.sendError(400,"Invalid Negotiate token");return;}
  HttpSession session=req.getSession(true);SpnegoAcceptor.Exchange x=(SpnegoAcceptor.Exchange)session.getAttribute(EXCHANGE);
  if(x==null){x=exchanges.begin();session.setAttribute(EXCHANGE,x);}
  final SpnegoAcceptor.Result g;
  try{g=x.accept(token);}
  catch(IllegalArgumentException e){x.close();session.removeAttribute(EXCHANGE);SecurityContextHolder.clearContext();challenge(res,null);return;}
  if(!g.established()){challenge(res,g.responseToken());return;}
  x.close();session.removeAttribute(EXCHANGE);
  var result=service.resolveEstablishedKerberosPrincipal(g.principal());
  var auth=new OpenIdentityAdAuthenticationToken(result);
  var context=SecurityContextHolder.createEmptyContext();context.setAuthentication(auth);SecurityContextHolder.setContext(context);
  if(g.responseToken().length>0)res.setHeader(HttpHeaders.WWW_AUTHENTICATE,"Negotiate "+Base64.getEncoder().encodeToString(g.responseToken()));
  chain.doFilter(req,res);
 }
 private static void challenge(HttpServletResponse res,byte[] token)throws IOException{
  String v="Negotiate";if(token!=null&&token.length>0)v+=" "+Base64.getEncoder().encodeToString(token);res.setHeader(HttpHeaders.WWW_AUTHENTICATE,v);res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);res.setContentType("application/json");res.getWriter().write("{\"status\":\"NEGOTIATE_REQUIRED\"}");
 }
}