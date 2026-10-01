package org.openidentity.spring;

import jakarta.servlet.http.HttpServletRequest;
import org.openidentity.oauth.ProfileError;
import org.openidentity.oauth.ProfileException;
import org.springframework.security.core.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.JwtException;
import java.util.*;

public final class OpenIdentityTokenExchangeAuthenticationConverter implements AuthenticationConverter {
 private static final String GRANT="urn:ietf:params:oauth:grant-type:token-exchange";
 private final ValidatedDpopJktResolver dpop;
 private final ActorNonceResolver nonce;

 public OpenIdentityTokenExchangeAuthenticationConverter(ValidatedDpopJktResolver dpop,ActorNonceResolver nonce){this.dpop=Objects.requireNonNull(dpop);this.nonce=Objects.requireNonNull(nonce);}

 @Override public Authentication convert(HttpServletRequest request){
  if(!GRANT.equals(one(request,"grant_type",false)))return null;
  String st=one(request,"subject_token_type",true),at=one(request,"actor_token_type",true);
  if(!OpenIdentityOAuthParameters.SUBJECT_TOKEN_TYPE.equals(st)||!OpenIdentityOAuthParameters.ACTOR_TOKEN_TYPE.equals(at))return null;
  Authentication client=SecurityContextHolder.getContext().getAuthentication();if(client==null||!client.isAuthenticated())throw OpenIdentityProfileErrorMapper.toOAuth(new ProfileException(ProfileError.INVALID_REQUEST));
  byte[] subject=decode(one(request,"subject_token",true)),actor=decode(one(request,"actor_token",true));
  byte[] expectedNonce=nonce.resolve(request);if(expectedNonce==null||expectedNonce.length==0)throw OpenIdentityProfileErrorMapper.toOAuth(new ProfileException(ProfileError.INVALID_REQUEST));
  ValidatedDpopProofResult validatedDpop;
  try{validatedDpop=dpop.resolve(request);}
  catch(JwtException e){throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_DPOP_PROOF,"The DPoP proof could not be accepted.",null),e);}
  if(validatedDpop==null)throw OpenIdentityProfileErrorMapper.toOAuth(new ProfileException(ProfileError.DPOP_REQUIRED));
  String requested=one(request,"requested_token_type",false);
  List<String> resources=many(request,"resource"),audiences=many(request,"audience");
  List<String> scopes=splitScopes(one(request,"scope",false));
  return new OpenIdentityTokenExchangeAuthenticationToken(client,subject,actor,expectedNonce,requested,validatedDpop,resources,audiences,scopes);
 }
 private static String one(HttpServletRequest r,String n,boolean required){
  String[] v=r.getParameterValues(n);if(v==null||v.length==0){if(required)bad();return null;}if(v.length!=1||v[0]==null||v[0].isEmpty())bad();return v[0];
 }
 private static List<String> many(HttpServletRequest r,String n){String[] v=r.getParameterValues(n);if(v==null)return List.of();for(String x:v)if(x==null||x.isEmpty())bad();return List.of(v);}
 private static List<String> splitScopes(String s){if(s==null)return List.of();String[] xs=s.split(" ",-1);for(String x:xs)if(x.isEmpty())bad();return List.of(xs);}
 private static byte[] decode(String s){try{if(s.indexOf('=')>=0)bad();return Base64.getUrlDecoder().decode(s);}catch(IllegalArgumentException e){bad();return null;}}
 private static void bad(){throw OpenIdentityProfileErrorMapper.toOAuth(new ProfileException(ProfileError.INVALID_REQUEST));}
}
