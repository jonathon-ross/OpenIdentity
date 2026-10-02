package org.openidentity.spring.ad;
import org.junit.jupiter.api.*;import org.openidentity.ad.*;import java.util.*;import org.springframework.mock.web.*;import org.springframework.security.core.context.SecurityContextHolder;
import static org.junit.jupiter.api.Assertions.*;
class OpenIdentitySpnegoAuthenticationFilterTest {
 @AfterEach void clear(){SecurityContextHolder.clearContext();}
 @Test void missingHeaderChallengesWithoutStartingDependencies()throws Exception{
  boolean[] began={false};SpnegoExchangeProvider p=()->{began[0]=true;throw new AssertionError("GSS must not start");};
  var filter=new OpenIdentitySpnegoAuthenticationFilter(p,unusedService());var req=new MockHttpServletRequest();var res=new MockHttpServletResponse();boolean[] called={false};
  filter.doFilter(req,res,(a,b)->called[0]=true);
  assertEquals(401,res.getStatus());assertEquals("Negotiate",res.getHeader("WWW-Authenticate"));assertFalse(called[0]);assertFalse(began[0]);
 }
 @Test void malformedTokenIsBadRequestWithoutStartingDependencies()throws Exception{
  boolean[] began={false};SpnegoExchangeProvider p=()->{began[0]=true;throw new AssertionError("GSS must not start");};
  var filter=new OpenIdentitySpnegoAuthenticationFilter(p,unusedService());var req=new MockHttpServletRequest();req.addHeader("Authorization","Negotiate !!!");var res=new MockHttpServletResponse();
  filter.doFilter(req,res,(a,b)->fail());
  assertEquals(400,res.getStatus());assertFalse(began[0]);
 }
 private static OpenIdentityActiveDirectoryService unusedService(){
  AdPrincipalResolver resolver=e->{throw new AssertionError("AD resolver must not run");};
  InMemoryExternalAdBindingRegistry.Policy policy=new InMemoryExternalAdBindingRegistry.Policy(){
   public boolean directoryTrusted(byte[] d){throw new AssertionError();}public boolean serviceAllowed(byte[] d,String s){throw new AssertionError();}public boolean mechanismAllowed(byte[] d,int m){throw new AssertionError();}public boolean identityActive(byte[] i){throw new AssertionError();}public long currentAuthenticationGeneration(byte[] i){throw new AssertionError();}
  };
  try{return new OpenIdentityActiveDirectoryService(resolver,new InMemoryExternalAdBindingRegistry(java.nio.file.Files.createTempFile("oi-ad-test",".store")),policy,"test","svc");}
  catch(java.io.IOException e){throw new RuntimeException(e);}
 }
 @Test void continuationReturnsNegotiateResponseToken()throws Exception{
  SpnegoExchangeProvider p=()->new FakeExchange(new SpnegoExchange.Result(false,null,new byte[]{1,2,3}),null);
  var filter=new OpenIdentitySpnegoAuthenticationFilter(p,unusedService());var req=request();var res=new MockHttpServletResponse();
  filter.doFilter(req,res,(a,b)->fail());
  assertEquals(401,res.getStatus());assertEquals("Negotiate AQID",res.getHeader("WWW-Authenticate"));
 }
 @Test void gssRejectionChallengesAndDoesNotReachAd()throws Exception{
  SpnegoExchangeProvider p=()->new FakeExchange(null,new IllegalArgumentException("bad GSS"));
  var filter=new OpenIdentitySpnegoAuthenticationFilter(p,unusedService());var req=request();var res=new MockHttpServletResponse();
  filter.doFilter(req,res,(a,b)->fail());
  assertEquals(401,res.getStatus());assertEquals("Negotiate",res.getHeader("WWW-Authenticate"));
 }
 private static MockHttpServletRequest request(){var r=new MockHttpServletRequest();r.addHeader("Authorization","Negotiate AQID");return r;}
 private static final class FakeExchange implements SpnegoExchange{
  private final Result result;private final RuntimeException error;FakeExchange(Result r,RuntimeException e){result=r;error=e;}
  public Result accept(byte[] token){if(error!=null)throw error;return result;}public void close(){}
 }
}