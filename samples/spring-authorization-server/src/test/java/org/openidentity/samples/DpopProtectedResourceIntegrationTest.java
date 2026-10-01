package org.openidentity.samples;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.oauth2.jwt.*;

import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
final class DpopProtectedResourceIntegrationTest {
 @LocalServerPort int port;
 @Autowired JwtEncoder jwtEncoder;
 private final HttpClient http=HttpClient.newHttpClient();

 @Test void matchingProofKeyAndAthAllowsProtectedRequest() throws Exception {
  ECKey key=key();String access=accessToken(key);
  HttpResponse<String> response=send(access,proof(key,"GET",resourceUri(),access,UUID.randomUUID().toString()));
  assertEquals(200,response.statusCode(),response.body());assertEquals("records",response.body());
 }

 @Test void proofSignedByDifferentKeyIsRejected() throws Exception {
  ECKey bound=key(),attacker=key();String access=accessToken(bound);
  HttpResponse<String> response=send(access,proof(attacker,"GET",resourceUri(),access,UUID.randomUUID().toString()));
  assertEquals(401,response.statusCode(),response.body());
 }

 @Test void wrongAccessTokenHashIsRejected() throws Exception {
  ECKey key=key();String access=accessToken(key);
  HttpResponse<String> response=send(access,proof(key,"GET",resourceUri(),"different-token",UUID.randomUUID().toString()));
  assertEquals(401,response.statusCode(),response.body());
 }

 @Test void wrongTargetUriIsRejected() throws Exception {
  ECKey key=key();String access=accessToken(key);
  HttpResponse<String> response=send(access,proof(key,"GET","http://127.0.0.1:"+port+"/api/wrong",access,UUID.randomUUID().toString()));
  assertEquals(401,response.statusCode(),response.body());
 }

 @Test void replayedProofIsRejected() throws Exception {
  ECKey key=key();String access=accessToken(key);
  String proof=proof(key,"GET",resourceUri(),access,UUID.randomUUID().toString());
  assertEquals(200,send(access,proof).statusCode());
  assertEquals(401,send(access,proof).statusCode());
 }

 private HttpResponse<String> send(String access,String proof) throws Exception {
  HttpRequest request=HttpRequest.newBuilder(URI.create(resourceUri()))
      .header("Authorization","DPoP "+access).header("DPoP",proof).GET().build();
  return http.send(request,HttpResponse.BodyHandlers.ofString());
 }

 private String accessToken(ECKey key) {
  Instant now=Instant.now();
  JwtClaimsSet claims=JwtClaimsSet.builder().issuer("http://127.0.0.1:9000").subject("subject")
      .issuedAt(now).expiresAt(now.plusSeconds(300)).claim("scope","records.read")
      .claim("cnf",Map.of("jkt",thumbprint(key))).build();
  return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
 }

 private static String proof(ECKey key,String method,String target,String access,String jti) throws Exception {
  var header=new com.nimbusds.jose.JWSHeader.Builder(JWSAlgorithm.ES256)
      .type(new JOSEObjectType("dpop+jwt")).jwk(key.toPublicJWK()).build();
  var claims=new JWTClaimsSet.Builder().claim("htm",method).claim("htu",target)
      .claim("ath",sha256(access)).issueTime(Date.from(Instant.now())).jwtID(jti).build();
  SignedJWT jwt=new SignedJWT(header,claims);jwt.sign(new ECDSASigner(key));return jwt.serialize();
 }

 private String resourceUri(){return "http://127.0.0.1:"+port+"/api/records";}
 private static ECKey key() throws Exception{return new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();}
 private static String thumbprint(ECKey key){try{return key.toPublicJWK().computeThumbprint().toString();}catch(Exception e){throw new IllegalStateException(e);}}
 private static String sha256(String value) throws Exception{
  byte[] digest=MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
  return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
 }
}
