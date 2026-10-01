package org.openidentity.spring.oidc;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import org.openidentity.oidc.*;
import org.springframework.security.core.*;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import java.io.IOException;
import java.util.Objects;

public final class OpenIdentityOidcLoginSuccessHandler implements AuthenticationSuccessHandler {
 public static final String SESSION_ATTRIBUTE="OPENIDENTITY_EXTERNAL_OIDC_AUTHENTICATION";
 private final ClientRegistrationRepository registrations;private final SpringExternalOidcAuthenticationResolver resolver;
 public OpenIdentityOidcLoginSuccessHandler(ClientRegistrationRepository registrations,SpringExternalOidcAuthenticationResolver resolver){this.registrations=Objects.requireNonNull(registrations);this.resolver=Objects.requireNonNull(resolver);}
 @Override public void onAuthenticationSuccess(HttpServletRequest request,HttpServletResponse response,Authentication authentication)throws IOException,ServletException{
  if(!(authentication instanceof OAuth2AuthenticationToken token)||!(token.getPrincipal() instanceof OidcUser user))throw new ServletException("OIDC authentication required");
  var registration=registrations.findByRegistrationId(token.getAuthorizedClientRegistrationId());if(registration==null)throw new ServletException("OIDC client registration unavailable");
  try{
   var resolved=resolver.resolve(user,registration,System.currentTimeMillis()/1000);
   request.getSession(true).setAttribute(SESSION_ATTRIBUTE,resolved);response.sendRedirect("/");
  }catch(ExternalOidcBindingException e){
   if(e.error()==ExternalOidcBindingError.BINDING_NOT_FOUND){response.sendRedirect("/openidentity/link");return;}
   throw new ServletException("OpenIdentity external identity resolution failed",e);
  }
 }
}
