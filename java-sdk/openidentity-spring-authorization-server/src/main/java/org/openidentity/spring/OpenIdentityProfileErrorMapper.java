package org.openidentity.spring;
import org.openidentity.oauth.*;
import org.springframework.security.oauth2.core.*;
public final class OpenIdentityProfileErrorMapper {
 private OpenIdentityProfileErrorMapper(){}
 public static OAuth2AuthenticationException toOAuth(ProfileException e){
  String code=switch(e.error()){
   case TARGET_SCOPE_PAIR_NOT_AUTHORIZED,UNSUPPORTED_REQUESTED_TOKEN_TYPE -> OAuth2ErrorCodes.INVALID_TARGET;
   default -> OAuth2ErrorCodes.INVALID_REQUEST;
  };
  return new OAuth2AuthenticationException(new OAuth2Error(code,"The token exchange request could not be accepted.",null),e);
 }
}
