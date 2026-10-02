package org.openidentity.spring.ad;
import org.junit.jupiter.api.*;import org.springframework.mock.web.*;import org.springframework.security.core.context.SecurityContextHolder;
import static org.junit.jupiter.api.Assertions.*;
class OpenIdentitySpnegoAuthenticationFilterTest {
 @AfterEach void clear(){SecurityContextHolder.clearContext();}
 @Test void missingHeaderChallengesWithoutStartingGss()throws Exception{
  boolean[] began={false};SpnegoExchangeProvider p=()->{began[0]=true;throw new AssertionError();};
  var filter=new OpenIdentitySpnegoAuthenticationFilter(p,null);var req=new MockHttpServletRequest();var res=new MockHttpServletResponse();boolean[] called={false};
  filter.doFilter(req,res,(a,b)->called[0]=true);
  assertEquals(401,res.getStatus());assertEquals("Negotiate",res.getHeader("WWW-Authenticate"));assertFalse(called[0]);assertFalse(began[0]);
 }
 @Test void malformedTokenIsBadRequestWithoutStartingGss()throws Exception{
  boolean[] began={false};SpnegoExchangeProvider p=()->{began[0]=true;throw new AssertionError();};
  var filter=new OpenIdentitySpnegoAuthenticationFilter(p,null);var req=new MockHttpServletRequest();req.addHeader("Authorization","Negotiate !!!");var res=new MockHttpServletResponse();
  filter.doFilter(req,res,(a,b)->fail());
  assertEquals(400,res.getStatus());assertFalse(began[0]);
 }
}