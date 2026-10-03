package org.openidentity.samples.nativeauth;
import com.fasterxml.jackson.databind.*;import com.fasterxml.jackson.databind.node.ObjectNode;import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;import org.bouncycastle.crypto.signers.Ed25519Signer;import org.openidentity.auth.*;import org.openidentity.core.*;import java.nio.file.*;import java.time.Instant;import java.util.*;
public final class NativeOi015Signer {
 public static void main(String[] args)throws Exception{
  if(args.length!=5){System.err.println("usage: NativeOi015Signer <challenge.json> <state-dir> <identity-hex> <method-id-hex> <private-seed-hex>");System.exit(2);}
  ObjectMapper json=new ObjectMapper();JsonNode c=json.readTree(Path.of(args[0]).toFile());HexFormat h=HexFormat.of();
  byte[] identity=h.parseHex(args[2]),methodId=h.parseHex(args[3]),seed=h.parseHex(args[4]);if(seed.length!=32)throw new IllegalArgumentException("private seed must be 32 bytes");
  CanonicalIdentityState state=new FileCanonicalIdentityStateRepository(Path.of(args[1])).resolve(identity);if(state==null)throw new IllegalArgumentException("identity state unavailable");
  boolean methodPresent=state.authenticationAuthority().methods().stream().anyMatch(m->Arrays.equals(m.methodId(),methodId));if(!methodPresent)throw new IllegalArgumentException("method not in current authentication authority");
  byte[] audience=h.parseHex(c.required("audienceHex").asText()),nonce=h.parseHex(c.required("nonceHex").asText()),context=h.parseHex(c.required("contextHashHex").asText());String purpose=c.required("purpose").asText();
  long now=Instant.now().getEpochSecond(),expires=Math.min(c.required("expiresAt").asLong(),now+60);if(expires<=now)throw new IllegalArgumentException("challenge expired");
  var raw=new AuthenticationAssertion(1,identity,state.stateHash(),state.authenticationAuthority().generation(),audience,purpose,now,expires,nonce,context,new byte[0]);byte[] exact=Oi015Codec.encodeAssertion(raw);
  var assertion=new AuthenticationAssertion(1,identity,state.stateHash(),state.authenticationAuthority().generation(),audience,purpose,now,expires,nonce,context,exact);
  var key=new Ed25519PrivateKeyParameters(seed,0);var signer=new Ed25519Signer();byte[] signing=AuthenticationAssertionCodec.signingBytes(assertion,methodId);signer.init(true,key);signer.update(signing,0,signing.length);byte[] sig=signer.generateSignature();
  byte[] secured=Oi015Codec.encode(assertion,List.of(new AuthenticationProof(methodId,sig)));
  ObjectNode out=json.createObjectNode();out.put("challengeId",c.required("challengeId").asText());out.put("assertionBase64Url",Base64.getUrlEncoder().withoutPadding().encodeToString(secured));System.out.println(json.writerWithDefaultPrettyPrinter().writeValueAsString(out));
 }
}