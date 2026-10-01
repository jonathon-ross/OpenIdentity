package org.openidentity.ad;
import org.junit.jupiter.api.Test;import java.util.*;import static org.junit.jupiter.api.Assertions.*;
final class DeterministicAdPrincipalResolverTest {
 @Test void resolvesOnlyConfiguredAuthenticatedPrincipalToExactLdapGuidOctets(){
  byte[] dir=HexFormat.of().parseHex("d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"),guid=HexFormat.of().parseHex("00112233445566778899aabbccddeeff");
  var r=new DeterministicAdPrincipalResolver(List.of(new DeterministicAdPrincipalResolver.Entry("lab","alice@OI-TEST.INTERNAL",dir,guid,true,true,Map.of("displayName","Alice Test"))));
  var p=r.resolve(new AdAuthenticationEvidence("lab","alice@OI-TEST.INTERNAL","openidentity-ad-link-service",ExternalAdBindingV1.KERBEROS_SPNEGO,true,Map.of("simulated",true)));
  assertArrayEquals(dir,p.directoryId());assertArrayEquals(guid,p.objectGuid());assertEquals("Alice Test",p.attributes().get("displayName"));assertTrue(p.channelTrusted());assertTrue(p.accountUsable());assertTrue(p.assuranceSufficient());
  assertThrows(ExternalAdBindingException.class,()->r.resolve(new AdAuthenticationEvidence("lab","alice","openidentity-ad-link-service",1,true,Map.of())));
 }
 @Test void namingAttributesDoNotBecomeIdentity(){
  byte[] dir=new byte[16],guid=new byte[16];guid[0]=7;var r=new DeterministicAdPrincipalResolver(List.of(new DeterministicAdPrincipalResolver.Entry("lab","principal",dir,guid,true,true,Map.of("upn","someone@example.test","dn","CN=Someone,DC=example,DC=test"))));
  var p=r.resolve(new AdAuthenticationEvidence("lab","principal","svc",1,true,Map.of()));assertArrayEquals(guid,p.objectGuid());assertFalse(Arrays.equals(p.objectGuid(),p.attributes().get("upn").toString().getBytes()));
 }
}