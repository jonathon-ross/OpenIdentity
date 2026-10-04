package org.openidentity.samples;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.proc.SecurityContext;
import org.openidentity.oauth.*;
import org.openidentity.spring.*;
import org.springframework.context.annotation.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.settings.*;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.Customizer;
import org.springframework.http.HttpMethod;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Clock;
import java.util.*;

@Configuration
public class AuthorizationServerConfig {
 static final AuthorizationGrantType TOKEN_EXCHANGE=new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:token-exchange");

 @Bean RegisteredClientRepository registeredClientRepository(){
  RegisteredClient agentClient=RegisteredClient.withId(UUID.randomUUID().toString()).clientId("agent-client").clientSecret("{noop}secret")
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantType(TOKEN_EXCHANGE)
      .scope("records.read").scope("records.write").build();

  RegisteredClient oidcClient=RegisteredClient.withId(UUID.randomUUID().toString()).clientId("openidentity-reference-client")
      .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .redirectUri("http://localhost:8081/login/oauth2/code/openidentity")
      .scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE)
      .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(true).build())
      .build();

  return new InMemoryRegisteredClientRepository(agentClient,oidcClient);
 }

 @Bean RSAKey rsaKey(){
  try{
   KeyPairGenerator g=KeyPairGenerator.getInstance("RSA");g.initialize(2048);KeyPair kp=g.generateKeyPair();
   return new RSAKey.Builder((RSAPublicKey)kp.getPublic()).privateKey((RSAPrivateKey)kp.getPrivate()).keyID(UUID.randomUUID().toString()).build();
  }catch(Exception e){throw new IllegalStateException(e);}
 }
 @Bean JWKSource<SecurityContext> jwkSource(RSAKey rsaKey){return new ImmutableJWKSet<>(new JWKSet(rsaKey));}
 @Bean JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource){return new NimbusJwtEncoder(jwkSource);}
 @Bean JwtDecoder jwtDecoder(RSAKey rsaKey){
  try{return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();}
  catch(com.nimbusds.jose.JOSEException e){throw new IllegalStateException(e);}
 }
 @Bean JwtGenerator jwtGenerator(JwtEncoder encoder){
  JwtGenerator g=new JwtGenerator(encoder);g.setJwtCustomizer(new OpenIdentityJwtCustomizer());return g;
 }
 @Bean OAuth2TokenGenerator<?> tokenGenerator(JwtGenerator jwt){return new DelegatingOAuth2TokenGenerator(jwt);}
 @Bean AuthorizationServerSettings authorizationServerSettings(){return AuthorizationServerSettings.builder().issuer("http://127.0.0.1:9000").build();}

 @Bean SampleOpenIdentityFixture.Material sampleMaterial(){return SampleOpenIdentityFixture.create();}
 @Bean DelegatedAgentExchangeService delegatedAgentExchangeService(SampleOpenIdentityFixture.Material material){return material.exchangeService();}
 @Bean ValidatedDpopJktResolver validatedDpopJktResolver(){return new SpringValidatedDpopProofResolver();}
 @Bean ActorNonceResolver actorNonceResolver(SampleOpenIdentityFixture.Material material){return request->material.nonce();}

 @Bean OpenIdentityTokenExchangeAuthenticationConverter openIdentityConverter(ValidatedDpopJktResolver dpop,ActorNonceResolver nonce){
  return new OpenIdentityTokenExchangeAuthenticationConverter(dpop,nonce);
 }
 @Bean OpenIdentitySpringTokenIssuer openIdentityTokenIssuer(@Qualifier("tokenGenerator") OAuth2TokenGenerator<?> generator){return new OpenIdentitySpringTokenIssuer(generator);}
 @Bean @ConditionalOnMissingBean(OpenIdentityExchange.class) OpenIdentityExchange openIdentityExchange(){
  return request->{
   long now=request.now();
   byte[] subject=new byte[32],actor=new byte[32];Arrays.fill(actor,(byte)7);
   List<String> audiences=request.resources().isEmpty()?request.audiences():request.resources();
   return new AuthorizationDecision(subject,actor,audiences,request.scopes(),request.dpop().jkt(),now,now+180);
  };
 }
 @Bean OpenIdentityTokenExchangeAuthenticationProvider openIdentityProvider(OpenIdentityExchange exchange,OpenIdentitySpringTokenIssuer issuer){
  return new OpenIdentityTokenExchangeAuthenticationProvider(exchange,"http://127.0.0.1:9000",Clock.systemUTC(),issuer);
 }

 @Bean @Order(2) SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http) throws Exception{
  http.securityMatcher("/api/**")
      .authorizeHttpRequests(a->a
          .requestMatchers(HttpMethod.GET,"/api/records/**").hasAuthority("SCOPE_records.read")
          .requestMatchers(HttpMethod.DELETE,"/api/records/**").hasAuthority("SCOPE_records.write")
          .anyRequest().authenticated())
      .oauth2ResourceServer(o->o.jwt(Customizer.withDefaults()).dPoP(Customizer.withDefaults()));
  return http.build();
 }

 @Bean @Order(1) SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,OpenIdentityTokenExchangeAuthenticationConverter converter,OpenIdentityTokenExchangeAuthenticationProvider provider) throws Exception{
  OpenIdentityAuthorizationServerConfigurer.configure(http,converter,provider);return http.build();
 }
}
