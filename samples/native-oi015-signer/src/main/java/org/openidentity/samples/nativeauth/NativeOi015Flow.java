package org.openidentity.samples.nativeauth;
import com.fasterxml.jackson.databind.*;import com.fasterxml.jackson.databind.node.ObjectNode;import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;import org.bouncycastle.crypto.signers.Ed25519Signer;import org.openidentity.auth.*;import org.openidentity.core.*;import java.net.*;import java.net.http.*;import java.nio.charset.StandardCharsets;import java.nio.file.*;import java.security.MessageDigest;import java.time.Instant;import java.util.*;import java.util.regex.*;
public final class NativeOi015Flow {
 public static void main(String[] args)throws Exception{
  if(args.length!=5&&args.length!=6){System.err.println("usage: NativeOi015Flow <server-base> [request-target] <state-dir> <identity-hex> <method-id-hex> <private-seed-hex>");System.err.println("       omit request-target to use the standard openidentity-reference-client authorization request");System.exit(2);}
  String base=args[0].replaceAll("/+$","");
  boolean referenceMode=args.length==5;
  String verifier=Base64.getUrlEncoder().withoutPadding().encodeToString("openidentity-native-oi015-reference-pkce-verifier".getBytes(StandardCharsets.UTF_8));
  String challenge=Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
  String target=referenceMode?"/oauth2/authorize?response_type=code&client_id=openidentity-reference-client&scope=openid%20profile&redirect_uri=http://localhost:8081/login/oauth2/code/openidentity&nonce=native-oi015-reference&code_challenge="+challenge+"&code_challenge_method=S256&state=native-oi015-reference":args[1];
  int offset=referenceMode?0:1;
  ObjectMapper json=new ObjectMapper();CookieManager cookies=new CookieManager(null,CookiePolicy.ACCEPT_ALL);HttpClient http=HttpClient.newBuilder().cookieHandler(cookies).followRedirects(HttpClient.Redirect.NEVER).build();
  ObjectNode challengeRequest=json.createObjectNode().put("requestTarget",target);HttpResponse<String> challengeResponse=http.send(HttpRequest.newBuilder(URI.create(base+"/openidentity/auth/login/challenge")).header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(challengeRequest))).build(),HttpResponse.BodyHandlers.ofString());
  if(challengeResponse.statusCode()!=200)throw new IllegalStateException("challenge HTTP "+challengeResponse.statusCode()+": "+challengeResponse.body());JsonNode c=json.readTree(challengeResponse.body());HexFormat h=HexFormat.of();
  byte[] identity=h.parseHex(args[2+offset]),methodId=h.parseHex(args[3+offset]),seed=h.parseHex(args[4+offset]);CanonicalIdentityState state=new FileCanonicalIdentityStateRepository(Path.of(args[1+offset])).resolve(identity);if(state==null)throw new IllegalArgumentException("identity state unavailable");
  if(state.authenticationAuthority().methods().stream().noneMatch(m->Arrays.equals(m.methodId(),methodId)))throw new IllegalArgumentException("method not current");
  byte[] audience=h.parseHex(c.required("audienceHex").asText()),nonce=h.parseHex(c.required("nonceHex").asText()),context=h.parseHex(c.required("contextHashHex").asText());long now=Instant.now().getEpochSecond(),expires=Math.min(c.required("expiresAt").asLong(),now+60);if(expires<=now)throw new IllegalArgumentException("challenge expired");
  var raw=new AuthenticationAssertion(1,identity,state.stateHash(),state.authenticationAuthority().generation(),audience,c.required("purpose").asText(),now,expires,nonce,context,new byte[0]);byte[] exact=Oi015Codec.encodeAssertion(raw);var assertion=new AuthenticationAssertion(1,identity,state.stateHash(),state.authenticationAuthority().generation(),audience,raw.purpose(),now,expires,nonce,context,exact);
  var key=new Ed25519PrivateKeyParameters(seed,0);byte[] signing=AuthenticationAssertionCodec.signingBytes(assertion,methodId);var signer=new Ed25519Signer();signer.init(true,key);signer.update(signing,0,signing.length);byte[] secured=Oi015Codec.encode(assertion,List.of(new AuthenticationProof(methodId,signer.generateSignature())));
  ObjectNode verify=json.createObjectNode().put("challengeId",c.required("challengeId").asText()).put("assertionBase64Url",Base64.getUrlEncoder().withoutPadding().encodeToString(secured));HttpResponse<String> verified=http.send(HttpRequest.newBuilder(URI.create(base+"/openidentity/auth/login/verify")).header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(verify))).build(),HttpResponse.BodyHandlers.ofString());
  if(verified.statusCode()!=200)throw new IllegalStateException("verify HTTP "+verified.statusCode()+": "+verified.body());JsonNode out=json.readTree(verified.body());ObjectNode result=json.createObjectNode();result.put("status",out.required("status").asText());result.put("identity",out.required("identity").asText());result.put("continue",base+out.required("continue").asText());cookies.getCookieStore().getCookies().stream().filter(x->x.getName().contains("SESSION")).findFirst().ifPresent(x->result.put("sessionCookieName",x.getName()));
  URI continuation=URI.create(base+out.required("continue").asText());HttpResponse<String> authorization=http.send(HttpRequest.newBuilder(continuation).GET().build(),HttpResponse.BodyHandlers.ofString());
  result.put("authorizationStatus",authorization.statusCode());String authorizationLocation=authorization.headers().firstValue("Location").orElse("");if(!authorizationLocation.isBlank())result.put("authorizationLocation",authorizationLocation);String authorizationBody=authorization.body();if(authorizationBody!=null&&!authorizationBody.isBlank())result.put("authorizationBody",authorizationBody);
  if(referenceMode&&authorization.statusCode()/100==3&&!authorizationLocation.isBlank()){
   String code=queryParam(URI.create(authorizationLocation).getRawQuery(),"code");if(code!=null)exchangeCode(http,json,result,base,code,verifier);
  }else if(referenceMode&&authorization.statusCode()==200&&authorizationBody!=null&&authorizationBody.contains("Consent required")){
   Matcher stateMatcher=Pattern.compile("name=\\\"state\\\" value=\\\"([^\\\"]+)\\\"").matcher(authorizationBody);if(!stateMatcher.find())throw new IllegalStateException("consent state unavailable");String consentState=stateMatcher.group(1);
   String form="client_id="+URLEncoder.encode("openidentity-reference-client",StandardCharsets.UTF_8)+"&state="+URLEncoder.encode(consentState,StandardCharsets.UTF_8)+"&scope="+URLEncoder.encode("profile",StandardCharsets.UTF_8);
   HttpResponse<String> consent=http.send(HttpRequest.newBuilder(URI.create(base+"/oauth2/authorize")).header("Content-Type","application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(form)).build(),HttpResponse.BodyHandlers.ofString());
   result.put("consentStatus",consent.statusCode());String location=consent.headers().firstValue("Location").orElse("");if(!location.isBlank())result.put("consentLocation",location);
   if(consent.statusCode()/100==3&&!location.isBlank()){
    URI redirect=URI.create(location);String code=queryParam(redirect.getRawQuery(),"code");if(code!=null)exchangeCode(http,json,result,base,code,verifier);
   }
  }
  String gateFailure=null;
  if(referenceMode){
   testWrongPkce(http,json,result,base,verifier,challenge);
   gateFailure=failedGate(result,h.formatHex(identity));
   if(gateFailure==null)result.put("gate","NATIVE OI-015 -> OAUTH2/OIDC END-TO-END: PASS");else result.put("gate","FAIL: "+gateFailure);
  }
  System.out.println(json.writerWithDefaultPrettyPrinter().writeValueAsString(result));
  if(gateFailure!=null)throw new IllegalStateException("END-TO-END GATE FAILED: "+gateFailure);
 }
 private static String failedGate(JsonNode result,String identity){
  if(!"AUTHENTICATED".equals(result.path("status").asText()))return "native OI-015 authentication";
  if(!result.path("identity").asText().equals(identity))return "authenticated identity continuity";
  int authorizationStatus=result.path("authorizationStatus").asInt();
  if(authorizationStatus!=200&&authorizationStatus/100!=3)return "OAuth authorization";
  if(authorizationStatus==200&&result.path("consentStatus").asInt()/100!=3)return "OAuth consent submission";
  if(!result.path("authorizationCodeReceived").asBoolean(false))return "authorization code issuance";
  if(result.path("tokenStatus").asInt()!=200)return "PKCE token exchange";
  if(!result.path("accessTokenReceived").asBoolean(false))return "access token issuance";
  if(!result.path("subjectMatchesIdentity").asBoolean(false))return "OIDC subject continuity";
  if(!result.path("authorizationCodeReplayRejected").asBoolean(false))return "authorization code replay rejection";
  if(!result.path("wrongPkceRejected").asBoolean(false))return "wrong PKCE verifier rejection";
  return null;
 }
 private static void testWrongPkce(HttpClient http,ObjectMapper json,ObjectNode result,String base,String verifier,String challenge)throws Exception{
  String attackTarget="/oauth2/authorize?response_type=code&client_id=openidentity-reference-client&scope=openid%20profile&redirect_uri=http://localhost:8081/login/oauth2/code/openidentity&nonce=native-oi015-pkce-negative&code_challenge="+challenge+"&code_challenge_method=S256&state=native-oi015-pkce-negative";
  HttpResponse<String> authorization=http.send(HttpRequest.newBuilder(URI.create(base+attackTarget)).GET().build(),HttpResponse.BodyHandlers.ofString());String location=authorization.headers().firstValue("Location").orElse("");
  if(authorization.statusCode()==200&&authorization.body()!=null&&authorization.body().contains("Consent required")){
   Matcher stateMatcher=Pattern.compile("name=\\\"state\\\" value=\\\"([^\\\"]+)\\\"").matcher(authorization.body());if(!stateMatcher.find())return;String form="client_id="+URLEncoder.encode("openidentity-reference-client",StandardCharsets.UTF_8)+"&state="+URLEncoder.encode(stateMatcher.group(1),StandardCharsets.UTF_8)+"&scope="+URLEncoder.encode("profile",StandardCharsets.UTF_8);HttpResponse<String> consent=http.send(HttpRequest.newBuilder(URI.create(base+"/oauth2/authorize")).header("Content-Type","application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(form)).build(),HttpResponse.BodyHandlers.ofString());location=consent.headers().firstValue("Location").orElse("");
  }
  if(location.isBlank())return;String code=queryParam(URI.create(location).getRawQuery(),"code");if(code==null)return;
  String wrongVerifier=verifier+"-wrong";String tokenForm="grant_type=authorization_code&client_id="+URLEncoder.encode("openidentity-reference-client",StandardCharsets.UTF_8)+"&code="+URLEncoder.encode(code,StandardCharsets.UTF_8)+"&redirect_uri="+URLEncoder.encode("http://localhost:8081/login/oauth2/code/openidentity",StandardCharsets.UTF_8)+"&code_verifier="+URLEncoder.encode(wrongVerifier,StandardCharsets.UTF_8);HttpResponse<String> token=http.send(HttpRequest.newBuilder(URI.create(base+"/oauth2/token")).header("Content-Type","application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(tokenForm)).build(),HttpResponse.BodyHandlers.ofString());result.put("wrongPkceStatus",token.statusCode());result.put("wrongPkceRejected",token.statusCode()>=400);
 }
 private static void exchangeCode(HttpClient http,ObjectMapper json,ObjectNode result,String base,String code,String verifier)throws Exception{
  result.put("authorizationCodeReceived",true);
  String tokenForm="grant_type=authorization_code&client_id="+URLEncoder.encode("openidentity-reference-client",StandardCharsets.UTF_8)+"&code="+URLEncoder.encode(code,StandardCharsets.UTF_8)+"&redirect_uri="+URLEncoder.encode("http://localhost:8081/login/oauth2/code/openidentity",StandardCharsets.UTF_8)+"&code_verifier="+URLEncoder.encode(verifier,StandardCharsets.UTF_8);
  HttpResponse<String> token=http.send(HttpRequest.newBuilder(URI.create(base+"/oauth2/token")).header("Content-Type","application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(tokenForm)).build(),HttpResponse.BodyHandlers.ofString());
  result.put("tokenStatus",token.statusCode());if(token.statusCode()==200){JsonNode tokens=json.readTree(token.body());result.put("accessTokenReceived",tokens.hasNonNull("access_token"));if(tokens.hasNonNull("id_token")){String[] parts=tokens.get("id_token").asText().split("\\.");if(parts.length==3){JsonNode claims=json.readTree(Base64.getUrlDecoder().decode(parts[1]));String subject=claims.path("sub").asText();result.put("idTokenSubject",subject);result.put("subjectMatchesIdentity",subject.equals(result.path("identity").asText()));}}
   HttpResponse<String> replay=http.send(HttpRequest.newBuilder(URI.create(base+"/oauth2/token")).header("Content-Type","application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(tokenForm)).build(),HttpResponse.BodyHandlers.ofString());result.put("authorizationCodeReplayStatus",replay.statusCode());result.put("authorizationCodeReplayRejected",replay.statusCode()>=400);
  }else result.put("tokenBody",token.body());
 }
 private static String queryParam(String query,String name){if(query==null)return null;for(String pair:query.split("&")){int i=pair.indexOf('=');String k=URLDecoder.decode(i<0?pair:pair.substring(0,i),StandardCharsets.UTF_8);if(k.equals(name))return URLDecoder.decode(i<0?"":pair.substring(i+1),StandardCharsets.UTF_8);}return null;}
}