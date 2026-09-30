package org.openidentity.samples;

import com.fasterxml.jackson.databind.*;
import org.junit.jupiter.api.Test;
import org.openidentity.spring.OpenIdentityOAuthParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
final class DelegatedAgentTokenExchangeIntegrationTest {
 @Autowired TestRestTemplate rest;
 @Autowired SampleOpenIdentityFixture.Material material;
 @Autowired JwtDecoder jwtDecoder;

 private HttpEntity<org.springframework.util.MultiValueMap<String,String>> request(){
  var form=new org.springframework.util.LinkedMultiValueMap<String,String>();
  form.add("grant_type","urn:ietf:params:oauth:grant-type:token-exchange");
  form.add("subject_token_type",OpenIdentityOAuthParameters.SUBJECT_TOKEN_TYPE);
  form.add("actor_token_type",OpenIdentityOAuthParameters.ACTOR_TOKEN_TYPE);
  form.add("subject_token",Base64.getUrlEncoder().withoutPadding().encodeToString(material.subjectToken()));
  form.add("actor_token",Base64.getUrlEncoder().withoutPadding().encodeToString(material.actorToken()));
  form.add("resource","https://api.example.test/");
  form.add("scope","records.read");
  HttpHeaders h=new HttpHeaders();h.setContentType(MediaType.APPLICATION_FORM_URLENCODED);h.setBasicAuth("agent-client","secret");
  return new HttpEntity<>(form,h);
 }

 @Test void exactOpenIdentityTokensProduceSignedSenderConstrainedAccessTokenAndReplayFails(){
  ResponseEntity<String> first=rest.postForEntity("/oauth2/token",request(),String.class);
  assertEquals(HttpStatus.OK,first.getStatusCode(),first.getBody());
  try{
   JsonNode json=new ObjectMapper().readTree(first.getBody());
   assertTrue(json.hasNonNull("access_token"));assertEquals("urn:ietf:params:oauth:token-type:access_token",json.path("issued_token_type").asText());
   assertFalse(json.has("refresh_token"));assertEquals("records.read",json.path("scope").asText());
   var jwt=jwtDecoder.decode(json.path("access_token").asText());
   assertEquals(material.dpopJkt(),((Map<?,?>)jwt.getClaim("cnf")).get("jkt"));
   assertEquals("records.read",jwt.getClaimAsString("scope"));assertNotNull(jwt.getClaim("act"));assertNotNull(jwt.getSubject());
  }catch(Exception e){throw new AssertionError(e);}

  ResponseEntity<String> replay=rest.postForEntity("/oauth2/token",request(),String.class);
  assertTrue(replay.getStatusCode().is4xxClientError(),replay.getBody());
  assertFalse(Objects.requireNonNullElse(replay.getBody(),"").contains("ASSERTION_REPLAY"));
 }
}
