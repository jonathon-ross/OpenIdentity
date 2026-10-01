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
import org.openidentity.spring.OpenIdentityOAuthParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.net.URI;
import java.net.http.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
final class DelegatedAgentTokenExchangeIntegrationTest {
 @LocalServerPort int port;
 @Autowired SampleOpenIdentityFixture.Material material;
 @Autowired JwtDecoder jwtDecoder;
 private final HttpClient http=HttpClient.newHttpClient();

 private HttpRequest request(ECKey dpopKey,String jti) throws Exception {
  Map<String,String> p=new LinkedHashMap<>();
  p.put("grant_type","urn:ietf:params:oauth:grant-type:token-exchange");
  p.put("subject_token_type",OpenIdentityOAuthParameters.SUBJECT_TOKEN_TYPE);
  p.put("actor_token_type",OpenIdentityOAuthParameters.ACTOR_TOKEN_TYPE);
  p.put("subject_token",Base64.getUrlEncoder().withoutPadding().encodeToString(material.subjectToken()));
  p.put("actor_token",Base64.getUrlEncoder().withoutPadding().encodeToString(material.actorToken()));
  p.put("resource","https://api.example.test/");p.put("scope","records.read");
  String body=p.entrySet().stream().map(e->enc(e.getKey())+"="+enc(e.getValue())).reduce((a,b)->a+"&"+b).orElse("");
  String basic=Base64.getEncoder().encodeToString("agent-client:secret".getBytes(StandardCharsets.UTF_8));
  String target="http://127.0.0.1:"+port+"/oauth2/token";
  return HttpRequest.newBuilder(URI.create(target))
      .header("Content-Type","application/x-www-form-urlencoded")
      .header("Authorization","Basic "+basic)
      .header("DPoP",dpopProof(dpopKey,target,jti))
      .POST(HttpRequest.BodyPublishers.ofString(body)).build();
 }

 private static String dpopProof(ECKey key,String target,String jti) throws Exception {
  var header=new com.nimbusds.jose.JWSHeader.Builder(JWSAlgorithm.ES256)
      .type(new JOSEObjectType("dpop+jwt")).jwk(key.toPublicJWK()).build();
  var claims=new JWTClaimsSet.Builder().claim("htm","POST").claim("htu",target)
      .issueTime(Date.from(Instant.now())).jwtID(jti).build();
  SignedJWT jwt=new SignedJWT(header,claims);jwt.sign(new ECDSASigner(key));return jwt.serialize();
 }

 private static String enc(String s){return URLEncoder.encode(s,StandardCharsets.UTF_8);}
 private static String jsonString(String json,String name){
  String key="\""+name+"\"";int k=json.indexOf(key);if(k<0)return null;int colon=json.indexOf(':',k+key.length()),q1=json.indexOf('"',colon+1);if(q1<0)return null;
  StringBuilder out=new StringBuilder();for(int i=q1+1;i<json.length();i++){char c=json.charAt(i);if(c=='"'&&(i==q1+1||json.charAt(i-1)!='\\'))return out.toString();out.append(c);}return null;
 }

 @Test void realDpopProofFlowsThroughFilterChainIntoSenderConstrainedJwt() throws Exception {
  ECKey dpopKey=new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
  String expectedJkt=dpopKey.toPublicJWK().computeThumbprint().toString();

  HttpResponse<String> first=http.send(request(dpopKey,UUID.randomUUID().toString()),HttpResponse.BodyHandlers.ofString());
  assertEquals(200,first.statusCode(),first.body());

  String access=jsonString(first.body(),"access_token"),issued=jsonString(first.body(),"issued_token_type"),scope=jsonString(first.body(),"scope");
  assertNotNull(access,first.body());
  assertEquals("urn:ietf:params:oauth:token-type:access_token",issued);
  assertEquals("records.read",scope);
  assertFalse(first.body().contains("\"refresh_token\""));

  var jwt=jwtDecoder.decode(access);
  assertEquals(expectedJkt,((Map<?,?>)jwt.getClaim("cnf")).get("jkt"));
  assertEquals("records.read",jwt.getClaimAsString("scope"));
  assertNotNull(jwt.getClaim("act"));
  assertNotNull(jwt.getSubject());
 }

 @Test void authorizationServerMetadataAdvertisesOpenIdentityInteropProfile() throws Exception {
  HttpRequest request=HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+"/.well-known/oauth-authorization-server")).GET().build();
  HttpResponse<String> response=http.send(request,HttpResponse.BodyHandlers.ofString());
  assertEquals(200,response.statusCode(),response.body());
  assertTrue(response.body().contains("\"urn:ietf:params:oauth:grant-type:token-exchange\""),response.body());
  assertTrue(response.body().contains("\"openidentity_token_exchange_profiles_supported\""),response.body());
  assertTrue(response.body().contains("\"https://openidentity.org/oauth/profile/delegated-agent-v1\""),response.body());
  assertTrue(response.body().contains("\"openidentity_subject_token_types_supported\""),response.body());
  assertTrue(response.body().contains("\""+OpenIdentityOAuthParameters.SUBJECT_TOKEN_TYPE+"\""),response.body());
  assertTrue(response.body().contains("\"openidentity_actor_token_types_supported\""),response.body());
  assertTrue(response.body().contains("\""+OpenIdentityOAuthParameters.ACTOR_TOKEN_TYPE+"\""),response.body());
  assertTrue(response.body().contains("\"openidentity_dpop_required\":true"),response.body());
  assertTrue(response.body().contains("\"openidentity_refresh_tokens_supported\":false"),response.body());
  assertTrue(response.body().contains("\"openidentity_max_access_token_lifetime_seconds\":300"),response.body());
 }

 @Test void replayedDpopProofIsRejectedAtHttpBoundary() throws Exception {
  ECKey dpopKey=new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
  String jti=UUID.randomUUID().toString();
  HttpRequest request=request(dpopKey,jti);

  HttpResponse<String> first=http.send(request,HttpResponse.BodyHandlers.ofString());
  assertEquals(200,first.statusCode(),first.body());

  HttpResponse<String> replay=http.send(request,HttpResponse.BodyHandlers.ofString());
  assertTrue(replay.statusCode()>=400&&replay.statusCode()<500,replay.body());
  assertFalse(replay.body().contains("ASSERTION_REPLAY"));
 }
}
