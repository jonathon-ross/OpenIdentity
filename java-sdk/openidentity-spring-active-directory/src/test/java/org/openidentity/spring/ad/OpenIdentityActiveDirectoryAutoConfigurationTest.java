package org.openidentity.spring.ad;
import org.junit.jupiter.api.*;import org.springframework.boot.autoconfigure.AutoConfigurations;import org.springframework.boot.context.properties.EnableConfigurationProperties;import org.springframework.boot.test.context.runner.ApplicationContextRunner;import org.springframework.context.annotation.Configuration;
import static org.junit.jupiter.api.Assertions.*;
class OpenIdentityActiveDirectoryAutoConfigurationTest {
 private final ApplicationContextRunner runner=new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(OpenIdentityActiveDirectoryAutoConfiguration.class));
 @Test void disabledContributesNoIntegrationBeans(){
  runner.withPropertyValues("openidentity.active-directory.enabled=false").run(c->{assertFalse(c.containsBean("openIdentitySpnegoAcceptor"));assertFalse(c.containsBean("openIdentityActiveDirectoryService"));assertFalse(c.containsBean("openIdentitySpnegoAuthenticationFilter"));});
 }
 @Test void enabledMissingRequiredConfigurationFailsClosed(){
  runner.withPropertyValues("openidentity.active-directory.enabled=true").run(c->{assertNotNull(c.getStartupFailure());String m=allMessages(c.getStartupFailure());assertTrue(m.contains("kerberos.service-principal")||m.contains("OPENIDENTITY_LDAP_BIND_PASSWORD"));});
 }
 @Test void propertiesBindWithoutStartingExternalIntegration(){
  new ApplicationContextRunner().withUserConfiguration(PropertiesOnly.class).withPropertyValues(
   "openidentity.active-directory.enabled=true",
   "openidentity.active-directory.kerberos.service-principal=HTTP/app.example.test@EXAMPLE.TEST",
   "openidentity.active-directory.kerberos.keytab=C:/secrets/service.keytab",
   "openidentity.active-directory.ldap.host=dc.example.test",
   "openidentity.active-directory.ldap.base-dn=DC=example,DC=test",
   "openidentity.active-directory.ldap.bind-principal=svc@example.test",
   "openidentity.active-directory.ldap.directory-id-hex=000102030405060708090a0b0c0d0e0f",
   "openidentity.active-directory.bindings.state-directory=C:/state",
   "openidentity.active-directory.bindings.store=C:/state/ad.store"
  ).run(c->{assertNull(c.getStartupFailure());var p=c.getBean(OpenIdentityActiveDirectoryProperties.class);assertTrue(p.isEnabled());assertEquals("HTTP/app.example.test@EXAMPLE.TEST",p.getKerberos().getServicePrincipal());assertEquals("dc.example.test",p.getLdap().getHost());assertEquals(636,p.getLdap().getPort());assertEquals("microsoft-ad",p.getLdap().getProfileId());});
 }
 @Configuration(proxyBeanMethods=false) @EnableConfigurationProperties(OpenIdentityActiveDirectoryProperties.class) static class PropertiesOnly{}
 private static String allMessages(Throwable t){StringBuilder b=new StringBuilder();while(t!=null){b.append(' ').append(t.getMessage());t=t.getCause();}return b.toString();}
}