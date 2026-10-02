package org.openidentity.spring;
import org.springframework.security.oauth2.core.OAuth2TokenType;import org.springframework.security.oauth2.server.authorization.token.*;import java.util.*;
public final class OpenIdentityJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
 @Override public void customize(JwtEncodingContext context){
  if(context.getPrincipal() instanceof OpenIdentityPrincipal p){
   byte[] id=p.openIdentityId();if(id==null||id.length!=32)throw new IllegalStateException("OpenIdentity principal must expose 32-byte identity");
   String subject=HexFormat.of().formatHex(id);context.getClaims().subject(subject);
   if(OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())||"id_token".equals(context.getTokenType().getValue()))context.getClaims().claim("oi_identity",subject);
  }
  var d=OpenIdentityDecisionResolver.from(context);if(d!=null)OpenIdentityJwtClaims.apply(context.getClaims(),d);
 }
}