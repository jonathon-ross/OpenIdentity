package org.openidentity.spring.oidc;

import jakarta.servlet.http.HttpSession;
import org.openidentity.oidc.VerifiedExternalOidcPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import java.security.SecureRandom;
import java.util.*;

public final class ExternalOidcBindingHttpSession {
 public static final String PENDING_ATTRIBUTE="OPENIDENTITY_EXTERNAL_OIDC_PENDING_BINDING";
 public record Request(String purpose,String contextHashHex,String audienceHex,String nonceHex){}
 private final SpringOidcPrincipalMapper mapper;private final ClientRegistrationRepository registrations;private final ExternalOidcBindingCeremony ceremony;private final SecureRandom random=new SecureRandom();
 public ExternalOidcBindingHttpSession(SpringOidcPrincipalMapper mapper,ClientRegistrationRepository registrations,ExternalOidcBindingCeremony ceremony){this.mapper=Objects.requireNonNull(mapper);this.registrations=Objects.requireNonNull(registrations);this.ceremony=Objects.requireNonNull(ceremony);}
 public Request begin(HttpSession session,OAuth2AuthenticationToken authentication,byte[] identity,long now,Long expiresAt){
  if(!(authentication.getPrincipal() instanceof OidcUser user))throw new IllegalArgumentException("OIDC principal required");
  var registration=registrations.findByRegistrationId(authentication.getAuthorizedClientRegistrationId());if(registration==null)throw new IllegalArgumentException("registration");
  VerifiedExternalOidcPrincipal principal=mapper.map(user,registration);var pending=ceremony.begin(principal,identity,now,expiresAt);
  byte[] audience=new byte[32],nonce=new byte[32];random.nextBytes(audience);random.nextBytes(nonce);
  session.setAttribute(PENDING_ATTRIBUTE,new PendingHttpBinding(pending,audience,nonce));
  var hex=HexFormat.of();return new Request(ExternalOidcBindingCeremony.BIND_PURPOSE,hex.formatHex(pending.contextHash()),hex.formatHex(audience),hex.formatHex(nonce));
 }
 public PendingHttpBinding pending(HttpSession session){Object p=session.getAttribute(PENDING_ATTRIBUTE);return p instanceof PendingHttpBinding b?b:null;}
 public void clear(HttpSession session){session.removeAttribute(PENDING_ATTRIBUTE);}
 public record PendingHttpBinding(ExternalOidcBindingCeremony.Pending pending,byte[] audience,byte[] nonce){
  public PendingHttpBinding{audience=audience.clone();nonce=nonce.clone();}@Override public byte[] audience(){return audience.clone();}@Override public byte[] nonce(){return nonce.clone();}
 }
}
