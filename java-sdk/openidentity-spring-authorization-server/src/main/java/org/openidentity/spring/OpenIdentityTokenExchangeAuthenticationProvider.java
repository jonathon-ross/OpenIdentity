package org.openidentity.spring;

import org.openidentity.oauth.*;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.*;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.*;

public final class OpenIdentityTokenExchangeAuthenticationProvider implements AuthenticationProvider {
 private final OpenIdentityExchange exchange;
 private final String authorizationServer;
 private final Clock clock;
 private final OpenIdentitySpringTokenIssuer tokenIssuer;

 public OpenIdentityTokenExchangeAuthenticationProvider(DelegatedAgentExchangeService exchange,String authorizationServer,Clock clock,OpenIdentitySpringTokenIssuer tokenIssuer){
  this(exchange::exchange,authorizationServer,clock,tokenIssuer);
 }
 public OpenIdentityTokenExchangeAuthenticationProvider(OpenIdentityExchange exchange,String authorizationServer,Clock clock,OpenIdentitySpringTokenIssuer tokenIssuer){
  this.exchange=Objects.requireNonNull(exchange);this.authorizationServer=Objects.requireNonNull(authorizationServer);this.clock=Objects.requireNonNull(clock);this.tokenIssuer=Objects.requireNonNull(tokenIssuer);
 }
 @Override public Authentication authenticate(Authentication authentication){
  var a=(OpenIdentityTokenExchangeAuthenticationToken)authentication;
  String clientId=clientId(a.clientPrincipal());
  var request=new DelegatedAgentExchangeRequest(authorizationServer,clientId,a.requestedTokenType(),a.resources(),a.audiences(),a.scopes(),
      a.subjectToken(),a.actorToken(),a.actorNonce(),new ValidatedDpopProof(a.dpopJkt()),clock.instant().getEpochSecond());
  try{
   var grant=new OpenIdentityAuthenticatedGrant(a.clientPrincipal(),exchange.exchange(request),a.dpop());
   if(!(a.clientPrincipal() instanceof OAuth2ClientAuthenticationToken client))throw OpenIdentityProfileErrorMapper.toOAuth(new ProfileException(ProfileError.INVALID_REQUEST));
   return tokenIssuer.issue(client,grant);
  }
  catch(ProfileException e){throw OpenIdentityProfileErrorMapper.toOAuth(e);}
 }
 private static String clientId(Authentication a){
  if(a instanceof OAuth2ClientAuthenticationToken c&&c.getRegisteredClient()!=null)return c.getRegisteredClient().getClientId();
  String n=a.getName();if(n==null||n.isBlank())throw OpenIdentityProfileErrorMapper.toOAuth(new ProfileException(ProfileError.INVALID_REQUEST));return n;
 }
 @Override public boolean supports(Class<?> authentication){return OpenIdentityTokenExchangeAuthenticationToken.class.isAssignableFrom(authentication);}
}
