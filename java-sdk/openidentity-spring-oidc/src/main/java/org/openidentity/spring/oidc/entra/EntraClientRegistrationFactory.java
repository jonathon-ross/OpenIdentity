package org.openidentity.spring.oidc.entra;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import java.util.Objects;

public final class EntraClientRegistrationFactory {
 private EntraClientRegistrationFactory(){}
 public static ClientRegistration create(String registrationId,String tenantId,String clientId,String clientSecret){
  Objects.requireNonNull(registrationId);Objects.requireNonNull(clientId);Objects.requireNonNull(clientSecret);
  EntraOidcProfile profile=new EntraOidcProfile(tenantId,java.util.Set.of(clientId));
  return ClientRegistration.withProviderConfiguration(
      java.util.Map.of("issuer",profile.issuerUri()),
      registrationId)
    .clientId(clientId).clientSecret(clientSecret).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
    .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
    .scope("openid","profile","email")
    .userNameAttributeName("sub").clientName("Microsoft Entra ID").build();
 }
}
