package org.openidentity.spring;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.jwt.JwtException;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

final class SpringValidatedDpopProofResolverTest {

 private static final String TOKEN_ENDPOINT = "https://issuer.example.test/oauth2/token";

 @Test void validatesSignedProofAndReturnsRfc7638Thumbprint() throws Exception {
  ECKey key = key();
  MockHttpServletRequest request = request(proof(key,key,"POST",TOKEN_ENDPOINT,Instant.now(),UUID.randomUUID().toString()));

  ValidatedDpopProofResult result = new SpringValidatedDpopProofResolver().resolve(request);

  assertNotNull(result);
  assertEquals(key.toPublicJWK().computeThumbprint().toString(),result.jkt());
  assertEquals("POST",result.proof().getClaimAsString("htm"));
  assertEquals(TOKEN_ENDPOINT,result.proof().getClaimAsString("htu"));
 }

 @Test void rejectsWrongHttpMethod() throws Exception {
  ECKey key = key();
  MockHttpServletRequest request = request(proof(key,key,"GET",TOKEN_ENDPOINT,Instant.now(),UUID.randomUUID().toString()));

  assertThrows(JwtException.class,()->new SpringValidatedDpopProofResolver().resolve(request));
 }

 @Test void rejectsWrongTargetUri() throws Exception {
  ECKey key = key();
  MockHttpServletRequest request = request(proof(key,key,"POST","https://issuer.example.test/wrong",Instant.now(),UUID.randomUUID().toString()));

  assertThrows(JwtException.class,()->new SpringValidatedDpopProofResolver().resolve(request));
 }

 @Test void rejectsStaleIssuedAt() throws Exception {
  ECKey key = key();
  MockHttpServletRequest request = request(proof(key,key,"POST",TOKEN_ENDPOINT,Instant.now().minusSeconds(600),UUID.randomUUID().toString()));

  assertThrows(JwtException.class,()->new SpringValidatedDpopProofResolver().resolve(request));
 }

 @Test void rejectsSignatureThatDoesNotMatchHeaderJwk() throws Exception {
  ECKey advertised = key();
  ECKey signer = key();
  MockHttpServletRequest request = request(proof(advertised,signer,"POST",TOKEN_ENDPOINT,Instant.now(),UUID.randomUUID().toString()));

  assertThrows(JwtException.class,()->new SpringValidatedDpopProofResolver().resolve(request));
 }

 @Test void rejectsReplayedJti() throws Exception {
  ECKey key = key();
  String compact = proof(key,key,"POST",TOKEN_ENDPOINT,Instant.now(),UUID.randomUUID().toString());
  SpringValidatedDpopProofResolver resolver = new SpringValidatedDpopProofResolver();

  assertNotNull(resolver.resolve(request(compact)));
  assertThrows(JwtException.class,()->resolver.resolve(request(compact)));
 }

 @Test void noDpopHeaderReturnsNull() {
  assertNull(new SpringValidatedDpopProofResolver().resolve(baseRequest()));
 }

 private static ECKey key() throws Exception {
  return new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
 }

 private static String proof(ECKey advertised,ECKey signingKey,String method,String target,Instant issuedAt,String jti) throws Exception {
  var header = new com.nimbusds.jose.JWSHeader.Builder(JWSAlgorithm.ES256)
      .type(new JOSEObjectType("dpop+jwt"))
      .jwk(advertised.toPublicJWK())
      .build();
  var claims = new JWTClaimsSet.Builder()
      .claim("htm",method)
      .claim("htu",target)
      .issueTime(Date.from(issuedAt))
      .jwtID(jti)
      .build();
  SignedJWT jwt = new SignedJWT(header,claims);
  jwt.sign(new ECDSASigner(signingKey));
  return jwt.serialize();
 }

 private static MockHttpServletRequest request(String proof) {
  MockHttpServletRequest request = baseRequest();
  request.addHeader("DPoP",proof);
  return request;
 }

 private static MockHttpServletRequest baseRequest() {
  MockHttpServletRequest request = new MockHttpServletRequest("POST","/oauth2/token");
  request.setScheme("https");
  request.setServerName("issuer.example.test");
  request.setServerPort(443);
  return request;
 }
}
