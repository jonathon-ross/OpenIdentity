package org.openidentity.samples.authserver;
import com.nimbusds.jose.jwk.*;import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;import com.nimbusds.jose.proc.SecurityContext;import com.nimbusds.jose.jwk.source.JWKSource;import com.nimbusds.jose.jwk.JWKSet;
import org.openidentity.spring.*;import org.springframework.boot.*;import org.springframework.boot.autoconfigure.SpringBootApplication;import org.springframework.context.annotation.*;import org.springframework.beans.factory.ObjectProvider;import org.springframework.security.web.context.SecurityContextHolderFilter;import org.springframework.core.annotation.Order;import org.springframework.security.config.Customizer;import org.springframework.security.config.annotation.web.builders.HttpSecurity;import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;import org.springframework.security.oauth2.jwt.JwtDecoder;import org.springframework.security.oauth2.core.*;import org.springframework.security.oauth2.server.authorization.client.*;import org.springframework.security.oauth2.server.authorization.settings.*;import org.springframework.security.oauth2.server.authorization.token.*;import org.springframework.security.web.SecurityFilterChain;import java.util.*;
@SpringBootApplication
public class AuthorizationServerReferenceApplication {
 public static void main(String[] a){SpringApplication.run(AuthorizationServerReferenceApplication.class,a);}
 @Bean @Order(1) SecurityFilterChain authorizationServer(HttpSecurity http,ObjectProvider<DevelopmentOpenIdentityPrincipalConfiguration.DevelopmentOpenIdentityPrincipalFilter> dev)throws Exception{
  var devFilter=dev.getIfAvailable();if(devFilter!=null)http.addFilterAfter(devFilter,SecurityContextHolderFilter.class);
  http.oauth2AuthorizationServer(as->as.oidc(Customizer.withDefaults()));
  http.authorizeHttpRequests(a->a.anyRequest().hasRole("OPENIDENTITY"));
  return http.build();
 }
 @Bean RegisteredClientRepository clients(){
  var c=RegisteredClient.withId(UUID.randomUUID().toString()).clientId("openidentity-reference-client").clientAuthenticationMethod(ClientAuthenticationMethod.NONE).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN).redirectUri("http://127.0.0.1:8081/login/oauth2/code/openidentity").scope("openid").scope("profile").clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(true).build()).build();
  return new InMemoryRegisteredClientRepository(c);
 }
 @Bean AuthorizationServerSettings settings(){return AuthorizationServerSettings.builder().issuer("http://127.0.0.1:9000").build();}
 @Bean JWKSource<SecurityContext> jwkSource()throws Exception{RSAKey key=new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();JWKSet set=new JWKSet(key);return (selector,ctx)->selector.select(set);}
 @Bean JwtDecoder jwtDecoder(JWKSource<SecurityContext> source){return OAuth2AuthorizationServerConfiguration.jwtDecoder(source);}
 @Bean OAuth2TokenCustomizer<JwtEncodingContext> openIdentityJwtCustomizer(){return new OpenIdentityJwtCustomizer();}
}