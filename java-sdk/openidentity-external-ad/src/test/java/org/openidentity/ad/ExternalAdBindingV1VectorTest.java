package org.openidentity.ad;

import com.fasterxml.jackson.databind.*;import org.junit.jupiter.api.Test;
import java.nio.file.*;import java.util.*;import static org.junit.jupiter.api.Assertions.*;

final class ExternalAdBindingV1VectorTest {
 @Test void ad01MatchesIndependentPythonReferenceByteForByte()throws Exception{
  Path p=Path.of("../../test-vectors/external-ad-binding-v1-crypto.json");JsonNode v=new ObjectMapper().readTree(Files.readString(p)).get("referenceVectors").get(0);var h=HexFormat.of();
  var b=new ExternalAdBindingV1.Binding(h.parseHex(v.get("identityHex").asText()),h.parseHex(v.get("directoryIdHex").asText()),h.parseHex(v.get("objectGuidLdapOctetsHex").asText()),v.get("serviceId").asText(),v.get("createdAt").asLong(),v.get("expiresAt").isNull()?null:v.get("expiresAt").asLong(),v.get("authenticationGeneration").asLong());
  byte[] bb=ExternalAdBindingV1.encode(b);assertEquals(v.get("bindingBytesHex").asText(),h.formatHex(bb));assertEquals(v.get("bindingIdHex").asText(),h.formatHex(ExternalAdBindingV1.bindingId(b)));var decoded=ExternalAdBindingV1.decode(bb);assertArrayEquals(b.identity(),decoded.identity());assertArrayEquals(b.directoryId(),decoded.directoryId());assertArrayEquals(b.objectGuid(),decoded.objectGuid());assertEquals(b.serviceId(),decoded.serviceId());assertEquals(b.createdAt(),decoded.createdAt());assertEquals(b.expiresAt(),decoded.expiresAt());assertEquals(b.authenticationGeneration(),decoded.authenticationGeneration());
  byte[] bc=ExternalAdBindingV1.encodeContext(ExternalAdBindingV1.BIND,b,v.get("authenticationMechanismCode").asInt(),h.parseHex(v.get("registryChallengeHex").asText()),null);assertEquals(v.get("bindContextBytesHex").asText(),h.formatHex(bc));assertEquals(v.get("bindContextHashHex").asText(),h.formatHex(ExternalAdBindingV1.contextHash(bc)));
  byte[] bid=h.parseHex(v.get("bindingIdHex").asText()),rc=ExternalAdBindingV1.encodeContext(ExternalAdBindingV1.REVOKE,b,v.get("authenticationMechanismCode").asInt(),h.parseHex(v.get("revokeRegistryChallengeHex").asText()),bid);assertEquals(v.get("revokeContextBytesHex").asText(),h.formatHex(rc));assertEquals(v.get("revokeContextHashHex").asText(),h.formatHex(ExternalAdBindingV1.contextHash(rc)));
 }
 @Test void objectGuidBytesAreOpaqueAndNotRuntimeGuidNormalized(){
  byte[] ldap=HexFormat.of().parseHex("00112233445566778899aabbccddeeff"),runtime=HexFormat.of().parseHex("33221100554477668899aabbccddeeff");assertFalse(Arrays.equals(ldap,runtime));
  var b=new ExternalAdBindingV1.Binding(new byte[32],new byte[16],ldap,"svc",1,null,0);assertArrayEquals(ldap,ExternalAdBindingV1.decode(ExternalAdBindingV1.encode(b)).objectGuid());assertFalse(Arrays.equals(runtime,ExternalAdBindingV1.decode(ExternalAdBindingV1.encode(b)).objectGuid()));
 }
}