package org.openidentity.spring;
import org.openidentity.oauth.*;
import org.springframework.security.oauth2.core.*;
public final class OpenIdentityProfileErrorMapper {
 public static final String INVALID_TARGET="invalid_target";
 private OpenIdentityProfileErrorMapper(){}
 public static OAuth2AuthenticationException toOAuth(ProfileException e){
  String code=switch(e.error()){
   case TARGET_SCOPE_PAIR_NOT_AUTHORIZED,UNSUPPORTED_REQUESTED_TOKEN_TYPE -> INVALID_TARGET;
   default -> OAuth2ErrorCodes.INVALID_REQUEST;
  };
  return new OAuth2AuthenticationException(new OAuth2Error(code,"The token exchange request could not be accepted.",null),e);
 }
}
