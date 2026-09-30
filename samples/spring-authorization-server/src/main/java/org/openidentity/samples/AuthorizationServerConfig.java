package org.openidentity.samples;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.proc.SecurityContext;
import org.openidentity.oauth.*;
import org.openidentity.spring.*;
import org.springframework.context.annotation.*;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.settings.*;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Clock;
import java.util.*;

@Configuration
public class AuthorizationServerConfig {
 static final AuthorizationGrantType TOKEN_EXCHANGE=new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:token-exchange");

 @Bean RegisteredClientRepository registeredClientRepository(){
  RegisteredClient client=RegisteredClient.withId(UUID.randomUUID().toString()).clientId("agent-client").clientSecret("{noop}secret")
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantType(TOKEN_EXCHANGE)
      .scope("records.read").scope("records.write").build();
  return new InMemoryRegisteredClientRepository(client);
 }

 @Bean JWKSource<SecurityContext> jwkSource(){
  try{
   KeyPairGenerator g=KeyPairGenerator.getInstance("RSA");g.initialize(2048);KeyPair kp=g.generateKeyPair();
   RSAKey rsa=new RSAKey.Builder((RSAPublicKey)kp.getPublic()).privateKey((RSAPrivateKey)kp.getPrivate()).keyID(UUID.randomUUID().toString()).build();
   return new ImmutableJWKSet<>(new JWKSet(rsa));
  }catch(Exception e){throw new IllegalStateException(e);}
 }

 @Bean JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource){return new NimbusJwtEncoder(jwkSource);}
 @Bean JwtGenerator jwtGenerator(JwtEncoder encoder){
  JwtGenerator g=new JwtGenerator(encoder);g.setJwtCustomizer(new OpenIdentityJwtCustomizer());return g;
 }
 @Bean OAuth2TokenGenerator<?> tokenGenerator(JwtGenerator jwt){return new DelegatingOAuth2TokenGenerator(jwt);}
 @Bean AuthorizationServerSettings authorizationServerSettings(){return AuthorizationServerSettings.builder().issuer("http://127.0.0.1:9000").build();}

 @Bean DelegatedAgentExchangeService delegatedAgentExchangeService(){
  // Sample boundary only; replaced next by exact OI-014/OI-015/OI-016 in-memory resolvers.
  DelegatedSubjectVerifier subject=b->{throw new ProfileException(ProfileError.INVALID_REQUEST);};
  AuthenticationAssertionVerifier actor=r->{throw new ProfileException(ProfileError.INVALID_REQUEST);};
  return new DelegatedAgentExchangeService(subject,actor,x->x,(s,t,scope)->true,id->true,300);
 }

 @Bean ValidatedDpopJktResolver validatedDpopJktResolver(){
  // The black-box exact-token fixture will replace this with the sample's validated DPoP adapter.
  return request->request.getHeader("X-Sample-Validated-DPoP-JKT");
 }
 @Bean ActorNonceResolver actorNonceResolver(){return request->{
  String v=request.getHeader("X-Sample-OI-Nonce");return v==null?null:Base64.getUrlDecoder().decode(v);
 };}

 @Bean OpenIdentityTokenExchangeAuthenticationConverter openIdentityConverter(ValidatedDpopJktResolver dpop,ActorNonceResolver nonce){
  return new OpenIdentityTokenExchangeAuthenticationConverter(dpop,nonce);
 }
 @Bean OpenIdentitySpringTokenIssuer openIdentityTokenIssuer(@Qualifier("tokenGenerator") OAuth2TokenGenerator<?> generator){return new OpenIdentitySpringTokenIssuer(generator);}
 @Bean OpenIdentityTokenExchangeAuthenticationProvider openIdentityProvider(DelegatedAgentExchangeService exchange,OpenIdentitySpringTokenIssuer issuer){
  return new OpenIdentityTokenExchangeAuthenticationProvider(exchange,"http://127.0.0.1:9000",Clock.systemUTC(),issuer);
 }

 @Bean @Order(1) SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,OpenIdentityTokenExchangeAuthenticationConverter converter,OpenIdentityTokenExchangeAuthenticationProvider provider) throws Exception{
  OpenIdentityAuthorizationServerConfigurer.configure(http,converter,provider);return http.build();
 }
}
