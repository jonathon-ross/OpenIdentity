package org.openidentity.oidc;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.openidentity.oidc.ExternalOidcBindingError.*;

final class ExternalOidcConformanceVectorsTest {
 private static final byte[] ID=HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
 private static final byte[] OTHER=HexFormat.of().parseHex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
 private static byte[] ch(int n){byte[] b=new byte[32];Arrays.fill(b,(byte)n);return b;}
 private long generation=3;private boolean trusted=true,identityActive=true,assurance=true;
 private final Set<String> clients=new HashSet<>(Set.of("openidentity-link-client","alternate-client"));
 private final InMemoryExternalOidcBindingRegistry.Policy policy=new InMemoryExternalOidcBindingRegistry.Policy(){
  public boolean providerTrusted(String issuer){return trusted&&(issuer.equals("https://idp.example.test")||issuer.equals("https://other.example.test"));}
  public boolean clientAllowed(String issuer,String clientId){return clients.contains(clientId);}
  public boolean identityActive(byte[] identity){return identityActive;}
  public long currentAuthenticationGeneration(byte[] identity){return generation;}
  public boolean assuranceSufficient(VerifiedExternalOidcPrincipal p){return assurance;}
 };
 private static VerifiedExternalOidcPrincipal p(String issuer,String subject,String client){return new VerifiedExternalOidcPrincipal(issuer,subject,client,1790841600L,"urn:acr:test",List.of("pwd"),Map.of());}
 private static VerifiedExternalOidcPrincipal base(){return p("https://idp.example.test","subject-123","openidentity-link-client");}
 private static InMemoryExternalOidcBindingRegistry.Authorization auth(String purpose){return new InMemoryExternalOidcBindingRegistry.Authorization(true,purpose,true,false);}
 private static InMemoryExternalOidcBindingRegistry.Authorization bind(){return auth("openidentity.external-oidc.bind");}
 private static InMemoryExternalOidcBindingRegistry.Authorization revoke(){return auth("openidentity.external-oidc.revoke");}
 private static void err(ExternalOidcBindingError e,Runnable r){assertEquals(e,assertThrows(ExternalOidcBindingException.class,r::run).error());}
 private InMemoryExternalOidcBindingRegistry bound(){var r=new InMemoryExternalOidcBindingRegistry();r.bind(base(),ID,1790841600L,null,ch(1),bind(),policy);return r;}

 @Test void B01_B02_validBindAndResolve(){var r=bound();assertArrayEquals(ID,r.resolve(base(),1790841660L,policy).identity());}
 @Test void B03_validRevoke(){var r=bound();var a=r.resolve(base(),1790841660L,policy);assertEquals(InMemoryExternalOidcBindingRegistry.Status.REVOKED,r.revoke(a.bindingId(),ch(2),1790841700L,revoke(),policy).status());}
 @Test void B04_generationResetInvalidates(){var r=bound();generation=4;err(BINDING_GENERATION_STALE,()->r.resolve(base(),1790841660L,policy));}
 @Test void B05_multipleExternalSubjectsMayBindSameIdentity(){var r=bound();r.bind(p("https://idp.example.test","subject-456","openidentity-link-client"),ID,1790841601L,null,ch(2),bind(),policy);assertArrayEquals(ID,r.resolve(p("https://idp.example.test","subject-456","openidentity-link-client"),1790841660L,policy).identity());}
 @Test void B06_alternateAllowedClientResolves(){var r=bound();assertArrayEquals(ID,r.resolve(p("https://idp.example.test","subject-123","alternate-client"),1790841660L,policy).identity());}

 @Test void BI01_differentIssuer(){var r=bound();err(BINDING_NOT_FOUND,()->r.resolve(p("https://other.example.test","subject-123","openidentity-link-client"),1790841660L,policy));}
 @Test void BI02_differentSubject(){var r=bound();err(BINDING_NOT_FOUND,()->r.resolve(p("https://idp.example.test","other","openidentity-link-client"),1790841660L,policy));}
 @Test void BI03_disallowedClient(){var r=bound();err(OIDC_CLIENT_NOT_ALLOWED,()->r.resolve(p("https://idp.example.test","subject-123","blocked"),1790841660L,policy));}
 @Test void BI04_emailOnlyCannotResolve(){var r=bound();err(BINDING_NOT_FOUND,()->r.resolve(p("https://idp.example.test","user@example.test","openidentity-link-client"),1790841660L,policy));}
 @Test void BI05_invalidOi015(){err(BINDING_AUTHORIZATION_INVALID,()->new InMemoryExternalOidcBindingRegistry().bind(base(),ID,1790841600L,null,ch(1),new InMemoryExternalOidcBindingRegistry.Authorization(false,"openidentity.external-oidc.bind",true,false),policy));}
 @Test void BI06_BI07_BI08_contextTupleMismatch(){for(int i=0;i<3;i++)err(BINDING_CONTEXT_MISMATCH,()->new InMemoryExternalOidcBindingRegistry().bind(base(),ID,1790841600L,null,ch(1),new InMemoryExternalOidcBindingRegistry.Authorization(true,"openidentity.external-oidc.bind",false,false),policy));}
 @Test void BI09_conflictingOwner(){var r=bound();err(BINDING_CONFLICT,()->r.bind(base(),OTHER,1790841601L,null,ch(2),bind(),policy));}
 @Test void BI10_revokedCannotResolve(){var r=bound();var a=r.resolve(base(),1790841660L,policy);r.revoke(a.bindingId(),ch(2),1790841700L,revoke(),policy);err(BINDING_REVOKED,()->r.resolve(base(),1790841800L,policy));}
 @Test void BI11_staleGeneration(){var r=bound();generation=4;err(BINDING_GENERATION_STALE,()->r.resolve(base(),1790841660L,policy));}
 @Test void BI12_inactiveIdentity(){var r=bound();identityActive=false;err(IDENTITY_INACTIVE,()->r.resolve(base(),1790841660L,policy));}
 @Test void BI13_untrustedIssuer(){var r=bound();trusted=false;err(OIDC_PROVIDER_UNTRUSTED,()->r.resolve(base(),1790841660L,policy));}
 @Test void BI14_adminOnlyBinding(){err(BINDING_AUTHORIZATION_INVALID,()->new InMemoryExternalOidcBindingRegistry().bind(base(),ID,1790841600L,null,ch(1),new InMemoryExternalOidcBindingRegistry.Authorization(false,"admin",true,false),policy));}
 @Test void BI15_bindingIdMismatch(){var r=bound();var b=new ExternalOidcBindingV1.Binding(ID,"https://idp.example.test","subject-123","openidentity-link-client",1790841600L,null,3);byte[] bytes=ExternalOidcBindingV1.encode(b),bad=ExternalOidcBindingV1.bindingId(bytes);bad[33]^=1;r.replaceStateForTest("https://idp.example.test","subject-123",new InMemoryExternalOidcBindingRegistry.State(bytes,bad,InMemoryExternalOidcBindingRegistry.Status.ACTIVE,null));err(BINDING_ID_MISMATCH,()->r.resolve(base(),1790841660L,policy));}
 @Test void BI16_expired(){var r=new InMemoryExternalOidcBindingRegistry();r.bind(base(),ID,1790841600L,1790841700L,ch(1),bind(),policy);err(BINDING_EXPIRED,()->r.resolve(base(),1790841700L,policy));}
 @Test void BI17_replayedChallenge(){var r=bound();err(BINDING_CHALLENGE_INVALID,()->r.bind(p("https://idp.example.test","subject-456","openidentity-link-client"),ID,1790841601L,null,ch(1),bind(),policy));}
 @Test void BI18_replayedAuthorization(){err(BINDING_REPLAY,()->new InMemoryExternalOidcBindingRegistry().bind(base(),ID,1790841600L,null,ch(1),new InMemoryExternalOidcBindingRegistry.Authorization(true,"openidentity.external-oidc.bind",true,true),policy));}
 @Test void BI19_bindPurposeCannotRevoke(){var r=bound();var a=r.resolve(base(),1790841660L,policy);err(BINDING_AUTHORIZATION_INVALID,()->r.revoke(a.bindingId(),ch(2),1790841700L,bind(),policy));}
 @Test void BI20_revokePurposeCannotBind(){err(BINDING_AUTHORIZATION_INVALID,()->new InMemoryExternalOidcBindingRegistry().bind(base(),ID,1790841600L,null,ch(1),revoke(),policy));}
 @Test void BI21_revokeDifferentBindingIdContext(){var r=bound();var a=r.resolve(base(),1790841660L,policy);err(BINDING_CONTEXT_MISMATCH,()->r.revoke(a.bindingId(),ch(2),1790841700L,new InMemoryExternalOidcBindingRegistry.Authorization(true,"openidentity.external-oidc.revoke",false,false),policy));}
 @Test void BI22_insufficientAssurance(){var r=bound();assurance=false;err(ASSURANCE_INSUFFICIENT,()->r.resolve(base(),1790841660L,policy));}
 @Test void BI23_malformedBindingBytes(){var r=bound();byte[] malformed=HexFormat.of().parseHex("a8011818");byte[] fake=new byte[34];fake[0]=0x12;fake[1]=0x20;r.replaceStateForTest("https://idp.example.test","subject-123",new InMemoryExternalOidcBindingRegistry.State(malformed,fake,InMemoryExternalOidcBindingRegistry.Status.ACTIVE,null));err(OIDC_PRINCIPAL_INVALID,()->r.resolve(base(),1790841660L,policy));}
}
