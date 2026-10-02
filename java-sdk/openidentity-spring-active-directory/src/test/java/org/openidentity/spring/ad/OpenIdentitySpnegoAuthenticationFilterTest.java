package org.openidentity.spring.ad;
import org.junit.jupiter.api.*;import org.openidentity.ad.spnego.SpnegoAcceptor;import org.springframework.mock.web.*;import org.springframework.security.core.context.SecurityContextHolder;import jakarta.servlet.*;import java.io.*;
import static org.junit.jupiter.api.Assertions.*;
class OpenIdentitySpnegoAuthenticationFilterTest {
 @AfterEach void clear(){SecurityContextHolder.clearContext();}
 @Test void missingHeaderChallengesWithoutCallingChain()throws Exception{
  var filter=new OpenIdentitySpnegoAuthenticationFilter(nullAcceptor(),nullService());var req=new MockHttpServletRequest();var res=new MockHttpServletResponse();boolean[] called={false};filter.doFilter(req,res,(a,b)->called[0]=true);assertEquals(401,res.getStatus());assertEquals("Negotiate",res.getHeader("WWW-Authenticate"));assertFalse(called[0]);
 }
 @Test void malformedTokenIsBadRequest()throws Exception{
  var filter=new OpenIdentitySpnegoAuthenticationFilter(nullAcceptor(),nullService());var req=new MockHttpServletRequest();req.addHeader("Authorization","Negotiate !!!");var res=new MockHttpServletResponse();filter.doFilter(req,res,(a,b)->fail());assertEquals(400,res.getStatus());
 }
 private static SpnegoAcceptor nullAcceptor(){return new SpnegoAcceptor("HTTP/invalid@INVALID",java.nio.file.Path.of("missing.keytab"));}
 private static OpenIdentityActiveDirectoryService nullService(){return null;}
}