package org.openidentity.spring;

import com.nimbusds.jose.jwk.JWK;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.jwt.*;
import java.net.URI;
import java.util.*;

public final class SpringValidatedDpopProofResolver implements ValidatedDpopJktResolver {
 private final DPoPProofJwtDecoderFactory decoders;
 public SpringValidatedDpopProofResolver(){this(new DPoPProofJwtDecoderFactory());}
 public SpringValidatedDpopProofResolver(DPoPProofJwtDecoderFactory decoders){this.decoders=Objects.requireNonNull(decoders);}
 @Override public ValidatedDpopProofResult resolve(HttpServletRequest request){
  String compact=request.getHeader("DPoP");if(compact==null||compact.isBlank())return null;
  String target=targetUri(request);
  DPoPProofContext context=DPoPProofContext.withDPoPProof(compact).method(request.getMethod()).targetUri(target).build();
  Jwt proof=decoders.createDecoder(context).decode(compact);
  Object jwkValue=proof.getHeaders().get("jwk");if(!(jwkValue instanceof Map<?,?> raw))throw new BadJwtException("DPoP proof missing public jwk");
  try{
   Map<String,Object> jwk=new LinkedHashMap<>();for(var e:raw.entrySet())jwk.put(String.valueOf(e.getKey()),e.getValue());
   String jkt=JWK.parse(jwk).computeThumbprint().toString();
   return new ValidatedDpopProofResult(jkt,proof);
  }catch(Exception e){throw new BadJwtException("Invalid DPoP public jwk",e);}
 }
 private static String targetUri(HttpServletRequest r){
  StringBuilder b=new StringBuilder();b.append(r.getScheme()).append("://").append(r.getServerName());
  int p=r.getServerPort();if(!(p==80&&"http".equalsIgnoreCase(r.getScheme()))&&!(p==443&&"https".equalsIgnoreCase(r.getScheme())))b.append(':').append(p);
  b.append(r.getRequestURI());return URI.create(b.toString()).toString();
 }
}
