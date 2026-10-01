package org.openidentity.oidc;
import org.junit.jupiter.api.*;import org.junit.jupiter.api.io.TempDir;import java.nio.file.*;import java.util.*;import static org.junit.jupiter.api.Assertions.*;
final class ExternalOidcBindingPersistenceTest{
 @TempDir Path dir;
 @Test void activeBindingAndConsumedChallengeSurviveRestart(){
  Path file=dir.resolve("bindings.store");byte[] id=new byte[32],challenge=new byte[32];challenge[0]=7;
  var policy=new InMemoryExternalOidcBindingRegistry.Policy(){public boolean providerTrusted(String i){return true;}public boolean clientAllowed(String i,String c){return true;}public boolean identityActive(byte[] i){return true;}public long currentAuthenticationGeneration(byte[] i){return 0;}public boolean assuranceSufficient(VerifiedExternalOidcPrincipal p){return true;}};
  var p=new VerifiedExternalOidcPrincipal("https://issuer","sub","client",null,null,List.of(),Map.of());var auth=new InMemoryExternalOidcBindingRegistry.Authorization(true,"openidentity.external-oidc.bind",true,false);
  new InMemoryExternalOidcBindingRegistry(file).bind(p,id,1L,null,challenge,auth,policy);
  var restarted=new InMemoryExternalOidcBindingRegistry(file);assertArrayEquals(id,restarted.resolve(p,2L,policy).identity());
  assertThrows(ExternalOidcBindingException.class,()->restarted.bind(p,id,3L,null,challenge,auth,policy));
 }
}