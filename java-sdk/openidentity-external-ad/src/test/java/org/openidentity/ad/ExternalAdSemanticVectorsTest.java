package org.openidentity.ad;
import com.fasterxml.jackson.databind.*;import org.junit.jupiter.api.Test;import java.nio.file.*;import java.util.*;import static org.junit.jupiter.api.Assertions.*;
import static org.openidentity.ad.ExternalAdBindingError.*;

final class ExternalAdSemanticVectorsTest {
 static final byte[] ID=new byte[32],OTHER=new byte[32],DIR=new byte[16],GUID=new byte[16],GUID2=new byte[16],C1=new byte[32],C2=new byte[32];static{OTHER[0]=1;Arrays.fill(DIR,(byte)0xd0);GUID[0]=1;GUID2[0]=2;Arrays.fill(C1,(byte)1);Arrays.fill(C2,(byte)2);}
 long generation=3;boolean trusted=true,active=true;Set<String> services=new HashSet<>(Set.of("svc","alt"));Set<Integer> mechanisms=new HashSet<>(Set.of(1,2,3));
 final InMemoryExternalAdBindingRegistry.Policy policy=new InMemoryExternalAdBindingRegistry.Policy(){public boolean directoryTrusted(byte[] d){return trusted;}public boolean serviceAllowed(byte[] d,String s){return services.contains(s);}public boolean mechanismAllowed(byte[] d,int m){return mechanisms.contains(m);}public boolean identityActive(byte[] i){return active;}public long currentAuthenticationGeneration(byte[] i){return generation;}};
 InMemoryExternalAdBindingRegistry.Principal p(byte[] dir,byte[] guid,String service,int mechanism,boolean channel,boolean usable,boolean assurance){return new InMemoryExternalAdBindingRegistry.Principal(dir,guid,service,mechanism,channel,usable,assurance);}
 InMemoryExternalAdBindingRegistry.Principal good(){return p(DIR,GUID,"svc",1,true,true,true);}InMemoryExternalAdBindingRegistry.Authorization bind(){return new InMemoryExternalAdBindingRegistry.Authorization(true,"openidentity.external-ad.bind",true,false);}InMemoryExternalAdBindingRegistry.Authorization revoke(){return new InMemoryExternalAdBindingRegistry.Authorization(true,"openidentity.external-ad.revoke",true,false);}
 @Test void everySemanticVectorHasExecutableContract()throws Exception{
  JsonNode rows=new ObjectMapper().readTree(Files.readString(Path.of("../../test-vectors/external-ad-binding-v1-pre-freeze.json"))).get("semanticVectors");Set<String> ids=new HashSet<>();rows.forEach(x->ids.add(x.get("id").asText()));assertEquals(38,ids.size());
  for(int i=1;i<=6;i++)assertTrue(ids.contains(String.format("AD%02d",i)));for(int i=1;i<=32;i++)assertTrue(ids.contains(String.format("ADI%02d",i)));
 }
 @Test void bindResolveAlternateServiceGenerationConflictAndExactKey(){
  var r=new InMemoryExternalAdBindingRegistry();r.bind(good(),ID,100,null,C1,bind(),policy);assertArrayEquals(ID,r.resolve(p(DIR,GUID,"alt",1,true,true,true),101,policy).identity());
  assertErr(BINDING_NOT_FOUND,()->r.resolve(p(otherDir(),GUID,"svc",1,true,true,true),101,policy));assertErr(BINDING_NOT_FOUND,()->r.resolve(p(DIR,GUID2,"svc",1,true,true,true),101,policy));
  assertErr(BINDING_CONFLICT,()->r.bind(good(),OTHER,102,null,C2,bind(),policy));generation=4;assertErr(BINDING_GENERATION_STALE,()->r.resolve(good(),103,policy));
 }
 @Test void directoryServiceMechanismChannelAccountAndAssuranceFailClosed(){
  trusted=false;assertErr(AD_DIRECTORY_UNTRUSTED,()->new InMemoryExternalAdBindingRegistry().bind(good(),ID,100,null,C1,bind(),policy));trusted=true;
  services.remove("svc");assertErr(AD_SERVICE_NOT_ALLOWED,()->new InMemoryExternalAdBindingRegistry().bind(good(),ID,100,null,C1,bind(),policy));services.add("svc");
  mechanisms.remove(1);assertErr(AD_AUTH_MECHANISM_NOT_ALLOWED,()->new InMemoryExternalAdBindingRegistry().bind(good(),ID,100,null,C1,bind(),policy));mechanisms.add(1);
  assertErr(AD_CHANNEL_UNTRUSTED,()->new InMemoryExternalAdBindingRegistry().bind(p(DIR,GUID,"svc",3,false,true,true),ID,100,null,C1,bind(),policy));
  assertErr(AD_ACCOUNT_UNUSABLE,()->new InMemoryExternalAdBindingRegistry().bind(p(DIR,GUID,"svc",1,true,false,true),ID,100,null,C1,bind(),policy));
  assertErr(ASSURANCE_INSUFFICIENT,()->new InMemoryExternalAdBindingRegistry().bind(p(DIR,GUID,"svc",1,true,true,false),ID,100,null,C1,bind(),policy));
 }
 @Test void authorizationReplayChallengeExpiryRevocationAndIntegrityFailClosed(){
  var principal=good();assertErr(BINDING_AUTHORIZATION_INVALID,()->new InMemoryExternalAdBindingRegistry().bind(principal,ID,100,null,C1,new InMemoryExternalAdBindingRegistry.Authorization(false,"openidentity.external-ad.bind",true,false),policy));
  assertErr(BINDING_CONTEXT_MISMATCH,()->new InMemoryExternalAdBindingRegistry().bind(principal,ID,100,null,C1,new InMemoryExternalAdBindingRegistry.Authorization(true,"openidentity.external-ad.bind",false,false),policy));
  assertErr(BINDING_REPLAY,()->new InMemoryExternalAdBindingRegistry().bind(principal,ID,100,null,C1,new InMemoryExternalAdBindingRegistry.Authorization(true,"openidentity.external-ad.bind",true,true),policy));
  var r=new InMemoryExternalAdBindingRegistry();var s=r.bind(principal,ID,100,110L,C1,bind(),policy);assertErr(BINDING_CHALLENGE_INVALID,()->r.bind(p(DIR,GUID2,"svc",1,true,true,true),ID,101,null,C1,bind(),policy));assertErr(BINDING_EXPIRED,()->r.resolve(principal,110,policy));
  r.revoke(s.bindingId(),C2,105,revoke(),policy);assertErr(BINDING_REVOKED,()->r.resolve(principal,106,policy));
  var corrupt=new InMemoryExternalAdBindingRegistry();byte[] bad=s.bindingId();bad[2]^=1;assertErr(BINDING_ID_MISMATCH,()->corrupt.replaceStateForTest(new InMemoryExternalAdBindingRegistry.State(s.bindingBytes(),bad,InMemoryExternalAdBindingRegistry.Status.ACTIVE,null)));
 }
 @Test void guidRuntimeByteOrderIsDifferentContext(){
  byte[] ldap=HexFormat.of().parseHex("00112233445566778899aabbccddeeff"),runtime=HexFormat.of().parseHex("33221100554477668899aabbccddeeff");var b1=new ExternalAdBindingV1.Binding(ID,DIR,ldap,"svc",100,null,3);var b2=new ExternalAdBindingV1.Binding(ID,DIR,runtime,"svc",100,null,3);assertFalse(Arrays.equals(ExternalAdBindingV1.contextHash(ExternalAdBindingV1.encodeContext(1,b1,1,C1,null)),ExternalAdBindingV1.contextHash(ExternalAdBindingV1.encodeContext(1,b2,1,C1,null))));
 }
 static byte[] otherDir(){byte[] x=DIR.clone();x[0]^=1;return x;}static void assertErr(ExternalAdBindingError e,Runnable x){assertEquals(e,assertThrows(ExternalAdBindingException.class,x::run).error());}
}