package org.openidentity.spring.ad;
import org.junit.jupiter.api.*;import org.openidentity.ad.*;import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
class OpenIdentityAdAuthenticationTokenTest {
 private static VerifiedAdPrincipal principal(){return new VerifiedAdPrincipal(new byte[16],new byte[16],"svc",ExternalAdBindingV1.KERBEROS_SPNEGO,true,true,true,Map.of());}
 @Test void unboundHasOnlyAdAuthority(){var r=new OpenIdentityActiveDirectoryAuthentication("alice@REALM",principal(),null,OpenIdentityActiveDirectoryAuthentication.BindingStatus.UNBOUND);var t=new OpenIdentityAdAuthenticationToken(r);assertEquals("alice@REALM",t.getPrincipal());assertTrue(t.getAuthorities().stream().anyMatch(a->a.getAuthority().equals("ROLE_AD_AUTHENTICATED")));assertFalse(t.getAuthorities().stream().anyMatch(a->a.getAuthority().equals("ROLE_OPENIDENTITY")));}
 @Test void activeUsesOpenIdentityAsPrincipal(){byte[] id=new byte[32];Arrays.fill(id,(byte)0xAB);var r=new OpenIdentityActiveDirectoryAuthentication("alice@REALM",principal(),id,OpenIdentityActiveDirectoryAuthentication.BindingStatus.ACTIVE);var t=new OpenIdentityAdAuthenticationToken(r);assertEquals("ab".repeat(32),t.getPrincipal());assertTrue(t.getAuthorities().stream().anyMatch(a->a.getAuthority().equals("ROLE_OPENIDENTITY")));}
 @Test void activeRequires32ByteIdentity(){assertThrows(IllegalArgumentException.class,()->new OpenIdentityActiveDirectoryAuthentication("alice@REALM",principal(),new byte[31],OpenIdentityActiveDirectoryAuthentication.BindingStatus.ACTIVE));}
}