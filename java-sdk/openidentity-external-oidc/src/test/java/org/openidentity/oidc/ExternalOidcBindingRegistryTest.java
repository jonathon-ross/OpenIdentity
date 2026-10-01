package org.openidentity.oidc;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.openidentity.oidc.ExternalOidcBindingError.*;

final class ExternalOidcBindingRegistryTest {
 private static final byte[] ID=java.util.HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
 private static final byte[] OTHER=java.util.HexFormat.of().parseHex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
 private static final byte[] C1=new byte[32],C2=new byte[32];
 static{Arrays.fill(C1,(byte)1);Arrays.fill(C2,(byte)2);}
 private long generation=3;private boolean trusted=true,active=true,assurance=true;
 private final Set<String> clients=new HashSet<>(Set.of("openidentity-link-client","alternate-client"));
 private final InMemoryExternalOidcBindingRegistry.Policy policy=new InMemoryExternalOidcBindingRegistry.Policy(){
  public boolean providerTrusted(String issuer){return trusted&&issuer.equals("https://idp.example.test");}
  public boolean clientAllowed(String issuer,String clientId){return clients.contains(clientId);}
  public boolean identityActive(byte[] identity){return active;}
  public long currentAuthenticationGeneration(byte[] identity){return generation;}
  public boolean assuranceSufficient(VerifiedExternalOidcPrincipal p){return assurance;}
 };
 private static VerifiedExternalOidcPrincipal p(String issuer,String sub,String client){return new VerifiedExternalOidcPrincipal(issuer,sub,client,1790841600L,"urn:acr:test",List.of("pwd"),Map.of());}
 private static InMemoryExternalOidcBindingRegistry.Authorization bindAuth(){return new InMemoryExternalOidcBindingRegistry.Authorization(true,"openidentity.external-oidc.bind",true,false);}
 private static InMemoryExternalOidcBindingRegistry.Authorization revokeAuth(){return new InMemoryExternalOidcBindingRegistry.Authorization(true,"openidentity.external-oidc.revoke",true,false);}
 private static void error(ExternalOidcBindingError e,Runnable r){assertEquals(e,assertThrows(ExternalOidcBindingException.class,r::run).error());}

 @Test void bindResolveAlternateClientAndGenerationReset(){
  var r=new InMemoryExternalOidcBindingRegistry();r.bind(p("https://idp.example.test","subject-123","openidentity-link-client"),ID,1790841600L,null,C1,bindAuth(),policy);
  assertArrayEquals(ID,r.resolve(p("https://idp.example.test","subject-123","alternate-client"),1790841660L,policy).identity());
  generation=4;error(BINDING_GENERATION_STALE,()->r.resolve(p("https://idp.example.test","subject-123","openidentity-link-client"),1790841660L,policy));
 }
 @Test void exactIssuerAndSubjectAreRequired(){
  var r=bound();error(BINDING_NOT_FOUND,()->r.resolve(p("https://other.example.test","subject-123","openidentity-link-client"),1790841660L,policy));
  error(BINDING_NOT_FOUND,()->r.resolve(p("https://idp.example.test","other","openidentity-link-client"),1790841660L,policy));
 }
 @Test void conflictingOwnerFailsClosed(){
  var r=bound();error(BINDING_CONFLICT,()->r.bind(p("https://idp.example.test","subject-123","openidentity-link-client"),OTHER,1790841700L,null,C2,bindAuth(),policy));
 }
 @Test void revokeIsTerminalForBindingId(){
  var r=bound();var s=r.resolve(p("https://idp.example.test","subject-123","openidentity-link-client"),1790841660L,policy);
  r.revoke(s.bindingId(),C2,1790841700L,revokeAuth(),policy);
  error(BINDING_REVOKED,()->r.resolve(p("https://idp.example.test","subject-123","openidentity-link-client"),1790841800L,policy));
 }
 @Test void clientProviderExpiryIdentityAndAssurancePoliciesFailClosed(){
  var r=boundWithExpiry(1790841700L);
  clients.remove("openidentity-link-client");error(OIDC_CLIENT_NOT_ALLOWED,()->r.resolve(p("https://idp.example.test","subject-123","openidentity-link-client"),1790841660L,policy));clients.add("openidentity-link-client");
  trusted=false;error(OIDC_PROVIDER_UNTRUSTED,()->r.resolve(p("https://idp.example.test","subject-123","openidentity-link-client"),1790841660L,policy));trusted=true;
  active=false;error(IDENTITY_INACTIVE,()->r.resolve(p("https://idp.example.test","subject-123","openidentity-link-client"),1790841660L,policy));active=true;
  assurance=false;error(ASSURANCE_INSUFFICIENT,()->r.resolve(p("https://idp.example.test","subject-123","openidentity-link-client"),1790841660L,policy));assurance=true;
  error(BINDING_EXPIRED,()->r.resolve(p("https://idp.example.test","subject-123","openidentity-link-client"),1790841700L,policy));
 }
 @Test void challengeAndAuthorizationFailuresArePinned(){
  var r=new InMemoryExternalOidcBindingRegistry();var principal=p("https://idp.example.test","subject-123","openidentity-link-client");
  r.bind(principal,ID,1790841600L,null,C1,bindAuth(),policy);
  error(BINDING_CHALLENGE_INVALID,()->r.bind(p("https://idp.example.test","subject-456","openidentity-link-client"),ID,1790841601L,null,C1,bindAuth(),policy));
  error(BINDING_AUTHORIZATION_INVALID,()->new InMemoryExternalOidcBindingRegistry().bind(principal,ID,1790841600L,null,C2,new InMemoryExternalOidcBindingRegistry.Authorization(false,"openidentity.external-oidc.bind",true,false),policy));
  error(BINDING_CONTEXT_MISMATCH,()->new InMemoryExternalOidcBindingRegistry().bind(principal,ID,1790841600L,null,C2,new InMemoryExternalOidcBindingRegistry.Authorization(true,"openidentity.external-oidc.bind",false,false),policy));
  error(BINDING_REPLAY,()->new InMemoryExternalOidcBindingRegistry().bind(principal,ID,1790841600L,null,C2,new InMemoryExternalOidcBindingRegistry.Authorization(true,"openidentity.external-oidc.bind",true,true),policy));
 }
 private InMemoryExternalOidcBindingRegistry bound(){return boundWithExpiry(null);}
 private InMemoryExternalOidcBindingRegistry boundWithExpiry(Long exp){var r=new InMemoryExternalOidcBindingRegistry();r.bind(p("https://idp.example.test","subject-123","openidentity-link-client"),ID,1790841600L,exp,C1,bindAuth(),policy);return r;}
}
