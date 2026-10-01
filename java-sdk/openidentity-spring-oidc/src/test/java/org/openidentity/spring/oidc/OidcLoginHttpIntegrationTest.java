package org.openidentity.spring.oidc;

import com.nimbusds.jose.*;import com.nimbusds.jose.crypto.RSASSASigner;import com.nimbusds.jose.jwk.*;import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;import com.nimbusds.jwt.*;
import com.sun.net.httpserver.HttpServer;
import org.eclipse.jetty.ee11.servlet.*;import org.eclipse.jetty.server.*;
import org.junit.jupiter.api.Test;
import org.openidentity.oidc.*;
import org.springframework.context.annotation.*;import org.springframework.security.config.Customizer;import org.springframework.security.config.annotation.web.builders.HttpSecurity;import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;import org.springframework.security.oauth2.client.registration.*;import org.springframework.security.oauth2.core.AuthorizationGrantType;import org.springframework.security.web.SecurityFilterChain;import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;import org.springframework.web.servlet.DispatcherServlet;
import java.io.*;import java.net.*;import java.net.http.*;import java.nio.charset.StandardCharsets;import java.time.Instant;import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class OidcLoginHttpIntegrationTest {
 @Test void realAuthorizationCodeLoginResolvesPreboundOpenIdentitySession() throws Exception {
  RSAKey key=new RSAKeyGenerator(2048).keyID("test-key").generate();HttpServer idp=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);int idpPort=idp.getAddress().getPort();String issuer="http://127.0.0.1:"+idpPort;Map<String,String> codeNonces=new java.util.concurrent.ConcurrentHashMap<>();
  idp.createContext("/jwks",x->json(x,200,new JWKSet(key.toPublicJWK()).toString()));
  idp.createContext("/authorize",x->{Map<String,String> q=query(x.getRequestURI().getRawQuery());codeNonces.put("code-1",q.getOrDefault("nonce",""));String location=q.get("redirect_uri")+"?code=code-1&state="+enc(q.get("state"));x.getResponseHeaders().add("Location",location);x.sendResponseHeaders(302,-1);x.close();});
  idp.createContext("/token",x->{Map<String,String> form=query(new String(x.getRequestBody().readAllBytes(),StandardCharsets.UTF_8));Instant now=Instant.now();JWTClaimsSet claims=new JWTClaimsSet.Builder().issuer(issuer).subject("subject-a").audience("client-1").issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(300))).claim("nonce",codeNonces.getOrDefault(form.get("code"),"")).build();SignedJWT jwt=new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("test-key").build(),claims);try{jwt.sign(new RSASSASigner(key));}catch(JOSEException e){json(x,500,"{\\\"error\\\":\\\"signing_failed\\\"}");return;}json(x,200,"{\"access_token\":\"access\",\"token_type\":\"Bearer\",\"expires_in\":300,\"id_token\":\""+jwt.serialize()+"\"}");});
  idp.start();

  var registry=new InMemoryExternalOidcBindingRegistry();byte[] identity=new byte[32],challenge=new byte[32];var policy=new InMemoryExternalOidcBindingRegistry.Policy(){public boolean providerTrusted(String i){return issuer.equals(i);}public boolean clientAllowed(String i,String c){return "client-1".equals(c);}public boolean identityActive(byte[] i){return true;}public long currentAuthenticationGeneration(byte[] i){return 3;}public boolean assuranceSufficient(VerifiedExternalOidcPrincipal p){return true;}};
  registry.bind(new VerifiedExternalOidcPrincipal(issuer,"subject-a","client-1",null,null,List.of(),Map.of()),identity,1790841600L,null,challenge,new InMemoryExternalOidcBindingRegistry.Authorization(true,"openidentity.external-oidc.bind",true,false),policy);

  Server app=new Server(new InetSocketAddress("127.0.0.1",0));ServletContextHandler context=new ServletContextHandler(ServletContextHandler.SESSIONS);app.setHandler(context);
  var parent=new org.springframework.context.support.GenericApplicationContext();parent.getBeanFactory().registerSingleton("clientRegistrationRepository",new InMemoryClientRegistrationRepository(ClientRegistration.withRegistrationId("test-idp").clientId("client-1").clientSecret("secret").clientAuthenticationMethod(org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_POST).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("{baseUrl}/login/oauth2/code/{registrationId}").scope("openid").authorizationUri(issuer+"/authorize").tokenUri(issuer+"/token").jwkSetUri(issuer+"/jwks").issuerUri(issuer).userNameAttributeName("sub").clientName("test").build()));parent.getBeanFactory().registerSingleton("resolver",new SpringExternalOidcAuthenticationResolver(new SpringOidcPrincipalMapper(),registry,policy));parent.refresh();
  AnnotationConfigWebApplicationContext spring=new AnnotationConfigWebApplicationContext();spring.setParent(parent);spring.register(AppConfig.class);spring.setServletContext(context.getServletContext());spring.refresh();context.addFilter(new org.eclipse.jetty.ee11.servlet.FilterHolder(new org.springframework.web.filter.DelegatingFilterProxy("springSecurityFilterChain",spring)),"/*",java.util.EnumSet.of(jakarta.servlet.DispatcherType.REQUEST));context.addServlet(new ServletHolder(new DispatcherServlet(spring)),"/");
  app.start();int appPort=((ServerConnector)app.getConnectors()[0]).getLocalPort();

  try{
   CookieManager cookies=new CookieManager();cookies.setCookiePolicy(CookiePolicy.ACCEPT_ALL);HttpClient client=HttpClient.newBuilder().cookieHandler(cookies).followRedirects(HttpClient.Redirect.ALWAYS).build();
   HttpResponse<String> response=client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+appPort+"/oauth2/authorization/test-idp")).GET().build(),HttpResponse.BodyHandlers.ofString());
   assertEquals(200,response.statusCode(),response.body());assertEquals("resolved",response.body());
  }finally{app.stop();spring.close();parent.close();idp.stop(0);}
 }

 @Configuration @EnableWebSecurity static class AppConfig {
  @Bean SecurityFilterChain chain(HttpSecurity http,ClientRegistrationRepository registrations,SpringExternalOidcAuthenticationResolver resolver)throws Exception{
   http.authorizeHttpRequests(a->a.requestMatchers("/").permitAll().anyRequest().authenticated()).oauth2Login(o->o.successHandler(new OpenIdentityOidcLoginSuccessHandler(registrations,resolver)).failureHandler(OidcLoginHttpIntegrationTest::writeFailure));return http.build();
  }
  @Bean org.springframework.web.servlet.function.RouterFunction<org.springframework.web.servlet.function.ServerResponse> routes(){return org.springframework.web.servlet.function.RouterFunctions.route().GET("/",r->{Object v=r.servletRequest().getSession(false)==null?null:r.servletRequest().getSession(false).getAttribute(OpenIdentityOidcLoginSuccessHandler.SESSION_ATTRIBUTE);return org.springframework.web.servlet.function.ServerResponse.ok().body(v instanceof ResolvedExternalOidcAuthentication?"resolved":"unresolved");}).build();}
 }
 private static void writeFailure(jakarta.servlet.http.HttpServletRequest request,jakarta.servlet.http.HttpServletResponse response,org.springframework.security.core.AuthenticationException exception)throws IOException{
  response.setStatus(401);response.setContentType("text/plain");
  StringBuilder m=new StringBuilder(exception.getClass().getName()).append(": ").append(exception.getMessage());
  for(Throwable cause=exception.getCause();cause!=null;cause=cause.getCause())m.append(System.lineSeparator()).append("CAUSED BY ").append(cause.getClass().getName()).append(": ").append(cause.getMessage());
  response.getWriter().write(m.toString());
 }
 private static Map<String,String> query(String s){Map<String,String> m=new HashMap<>();if(s==null)return m;for(String p:s.split("&")){String[] a=p.split("=",2);m.put(dec(a[0]),a.length>1?dec(a[1]):"");}return m;}
 private static String enc(String s){return URLEncoder.encode(s,StandardCharsets.UTF_8);}private static String dec(String s){return URLDecoder.decode(s,StandardCharsets.UTF_8);}
 private static void json(com.sun.net.httpserver.HttpExchange x,int code,String body)throws IOException{byte[] b=body.getBytes(StandardCharsets.UTF_8);x.getResponseHeaders().add("Content-Type","application/json");x.sendResponseHeaders(code,b.length);x.getResponseBody().write(b);x.close();}
}
