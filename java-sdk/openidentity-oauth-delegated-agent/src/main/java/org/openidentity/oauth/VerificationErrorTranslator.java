package org.openidentity.oauth;
import org.openidentity.core.*;
public final class VerificationErrorTranslator {
 private VerificationErrorTranslator(){}
 public static ProfileException toProfile(VerificationException e){
  ProfileError p=switch(e.error()){
   case STATE_UNAVAILABLE -> ProfileError.DELEGATION_STATE_UNAVAILABLE;
   case NOT_CURRENTLY_USABLE -> ProfileError.DELEGATION_NOT_CURRENTLY_USABLE;
   case ACTOR_BINDING_MISMATCH -> ProfileError.ACTOR_BINDING_MISMATCH;
   case ASSERTION_CONTEXT_BINDING_MISMATCH -> ProfileError.ASSERTION_CONTEXT_BINDING_MISMATCH;
   case CAPABILITY_PROFILE_UNAVAILABLE -> ProfileError.CAPABILITY_PROFILE_MAPPING_UNAVAILABLE;
   case AUTHORITY_NOT_PERMITTED -> ProfileError.TARGET_SCOPE_PAIR_NOT_AUTHORIZED;
   case INVALID_INPUT -> ProfileError.INVALID_REQUEST;
  };
  return new ProfileException(p,e);
 }
}