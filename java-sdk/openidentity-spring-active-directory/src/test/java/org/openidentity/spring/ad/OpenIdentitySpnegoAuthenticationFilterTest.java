package org.openidentity.spring.ad;
import org.junit.jupiter.api.*;import org.openidentity.ad.*;import java.util.*;import org.springframework.mock.web.*;import org.springframework.security.core.context.SecurityContextHolder;
import static org.junit.jupiter.api.Assertions.*;
class OpenIdentitySpnegoAuthenticationFilterTest {
 @AfterEach void clear(){SecurityContextHolder.clearContext();}
 @Test void missingHeaderPassesDownstreamWithoutStartingDependencies()throws Exception{
  boolean[] began={false};SpnegoExchangeProvider p=()->{began[0]=true;throw new AssertionError("GSS must not start");};
  var filter=new OpenIdentitySpnegoAuthenticationFilter(p,unusedService());var req=new MockHttpServletRequest();var res=new MockHttpServletResponse();boolean[] called={false};
  filter.doFilter(req,res,(a,b)->called[0]=true);
  assertEquals(200,res.getStatus());assertNull(res.getHeader("WWW-Authenticate"));assertTrue(called[0]);assertFalse(began[0]);
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
 @Test void establishedUnboundPrincipalPopulatesAdOnlySecurityContext()throws Exception{
  var filter=new OpenIdentitySpnegoAuthenticationFilter(established(),service(false,false));var req=request();var res=new MockHttpServletResponse();boolean[] called={false};
  filter.doFilter(req,res,(a,b)->called[0]=true);
  assertTrue(called[0]);var a=(OpenIdentityAdAuthenticationToken)SecurityContextHolder.getContext().getAuthentication();assertNotNull(a);assertEquals("alice@OI-TEST.INTERNAL",a.getPrincipal());assertFalse(a.result().bound());assertTrue(a.getAuthorities().stream().anyMatch(x->x.getAuthority().equals("ROLE_AD_AUTHENTICATED")));assertFalse(a.getAuthorities().stream().anyMatch(x->x.getAuthority().equals("ROLE_OPENIDENTITY")));
 }
 @Test void establishedActiveBindingUsesOpenIdentityPrincipal()throws Exception{
  var filter=new OpenIdentitySpnegoAuthenticationFilter(established(),service(true,false));var req=request();var res=new MockHttpServletResponse();
  filter.doFilter(req,res,(a,b)->{});
  var a=(OpenIdentityAdAuthenticationToken)SecurityContextHolder.getContext().getAuthentication();assertNotNull(a);assertEquals("42".repeat(32),a.getPrincipal());assertTrue(a.result().bound());assertTrue(a.getAuthorities().stream().anyMatch(x->x.getAuthority().equals("ROLE_OPENIDENTITY")));
 }
 @Test void downstreamAdFailurePropagatesInsteadOfRechallenging()throws Exception{
  var filter=new OpenIdentitySpnegoAuthenticationFilter(established(),service(false,true));var req=request();var res=new MockHttpServletResponse();
  IllegalStateException e=assertThrows(IllegalStateException.class,()->filter.doFilter(req,res,(a,b)->fail()));assertEquals("directory unavailable",e.getMessage());assertNull(res.getHeader("WWW-Authenticate"));
 }
 private static SpnegoExchangeProvider established(){return ()->new FakeExchange(new SpnegoExchange.Result(true,"alice@OI-TEST.INTERNAL",new byte[0]),null);}
 private static OpenIdentityActiveDirectoryService service(boolean active,boolean fail){
  byte[] directory=new byte[16],guid=new byte[16],identity=new byte[32];Arrays.fill(identity,(byte)0x42);
  AdPrincipalResolver resolver=e->{if(fail)throw new IllegalStateException("directory unavailable");return new VerifiedAdPrincipal(directory,guid,"svc",ExternalAdBindingV1.KERBEROS_SPNEGO,true,true,true,Map.of());};
  InMemoryExternalAdBindingRegistry.Policy policy=new InMemoryExternalAdBindingRegistry.Policy(){public boolean directoryTrusted(byte[] d){return true;}public boolean serviceAllowed(byte[] d,String s){return true;}public boolean mechanismAllowed(byte[] d,int m){return true;}public boolean identityActive(byte[] i){return true;}public long currentAuthenticationGeneration(byte[] i){return 0;}};
  try{
   var registry=new InMemoryExternalAdBindingRegistry(java.nio.file.Files.createTempFile("oi-ad-test",".store"));
   if(active){var p=resolver.resolve(null);registry.bind(ExternalAdPrincipalBridge.registryPrincipal(p),identity,System.currentTimeMillis()/1000,null,new byte[32],new InMemoryExternalAdBindingRegistry.Authorization(true,"openidentity.external-ad.bind",true,false),policy);}
   return new OpenIdentityActiveDirectoryService(resolver,registry,policy,"test","svc");
  }catch(java.io.IOException e){throw new RuntimeException(e);}
 }
}