package org.openidentity.ad.ldap;
import com.unboundid.ldap.listener.*;import com.unboundid.ldap.sdk.*;import org.junit.jupiter.api.*;import org.openidentity.ad.*;import java.util.*;import static org.junit.jupiter.api.Assertions.*;
final class LdapAdPrincipalResolverIntegrationTest {
 InMemoryDirectoryServer ds;
 @BeforeEach void start()throws Exception{
  var cfg=new InMemoryDirectoryServerConfig("dc=oi-test,dc=internal");cfg.setSchema(null);cfg.addAdditionalBindCredentials("cn=svc,dc=oi-test,dc=internal","secret");ds=new InMemoryDirectoryServer(cfg);ds.startListening();
  ds.add(new Entry("dc=oi-test,dc=internal",new Attribute("objectClass","top","domain"),new Attribute("dc","oi-test")));
  byte[] guid=HexFormat.of().parseHex("00112233445566778899aabbccddeeff");
  ds.add(new Entry("cn=Alice,dc=oi-test,dc=internal",new Attribute("objectClass","top","person","organizationalPerson","inetOrgPerson"),new Attribute("cn","Alice"),new Attribute("sn","Test"),new Attribute("userPrincipalName","alice@OI-TEST.INTERNAL"),new Attribute("objectGUID",guid),new Attribute("userAccountControl","512")));
 }
 @AfterEach void stop(){ds.shutDown(true);}
 @Test void retrievesExactBinaryObjectGuid() {
  byte[] dir=HexFormat.of().parseHex("d0d1d2d3d4d5d6d7d8d9dadbdcdddedf");var profile=new LdapAdPrincipalResolver.Profile("lab","127.0.0.1",ds.getListenPort(),"dc=oi-test,dc=internal","cn=svc,dc=oi-test,dc=internal","secret",dir,false);var r=new LdapAdPrincipalResolver(profile);
  var p=r.resolve(new AdAuthenticationEvidence("lab","alice@OI-TEST.INTERNAL","openidentity-ad-link-service",ExternalAdBindingV1.KERBEROS_SPNEGO,true,Map.of("authenticatedUpstream",true)));
  assertArrayEquals(dir,p.directoryId());assertArrayEquals(HexFormat.of().parseHex("00112233445566778899aabbccddeeff"),p.objectGuid());assertTrue(p.accountUsable());assertEquals("alice@OI-TEST.INTERNAL",p.attributes().get("upn"));
 }
 @Test void missingPrincipalAndWrongDirectoryFailClosed(){
  byte[] dir=new byte[16];var r=new LdapAdPrincipalResolver(new LdapAdPrincipalResolver.Profile("lab","127.0.0.1",ds.getListenPort(),"dc=oi-test,dc=internal","cn=svc,dc=oi-test,dc=internal","secret",dir,false));
  assertEquals(ExternalAdBindingError.AD_PRINCIPAL_INVALID,assertThrows(ExternalAdBindingException.class,()->r.resolve(new AdAuthenticationEvidence("lab","nobody@OI-TEST.INTERNAL","svc",1,true,Map.of()))).error());
  assertEquals(ExternalAdBindingError.AD_DIRECTORY_UNTRUSTED,assertThrows(ExternalAdBindingException.class,()->r.resolve(new AdAuthenticationEvidence("other","alice@OI-TEST.INTERNAL","svc",1,true,Map.of()))).error());
 }
}