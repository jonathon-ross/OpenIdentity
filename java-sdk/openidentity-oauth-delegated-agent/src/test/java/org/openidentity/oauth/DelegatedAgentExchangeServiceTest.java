package org.openidentity.oauth;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.*;

final class DelegatedAgentExchangeServiceTest {
    static byte[] h(String s){try{return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));}catch(Exception e){throw new RuntimeException(e);}}
    static byte[] mh(String s){byte[] d=h(s),o=new byte[34];o[0]=0x12;o[1]=0x20;System.arraycopy(d,0,o,2,32);return o;}
    static String jkt(){return Base64.getUrlEncoder().withoutPadding().encodeToString(h("service dpop"));}

    record Fixture(DelegatedAgentExchangeRequest request,VerifiedDelegatedSubject subject,VerifiedAuthenticationAssertion actor){}

    Fixture fixture(){
        long now=2_004_000_000L;byte[] root=h("root"),delegate=h("delegate"),aid=mh("assertion"),eid=mh("evidence");
        var context=new OAuthTokenExchangeContextV1("https://as.example.test","client",null,
                List.of("https://api.example.test/"),List.of(),List.of("read"),eid,jkt());
        var subject=new VerifiedDelegatedSubject(root,delegate,aid,eid,now+180,List.of());
        var actor=new VerifiedAuthenticationAssertion(delegate,aid,OAuthTokenExchangeContextV1Encoder.contextHash(context),DelegatedAgentProfileVerifier.PURPOSE);
        var request=new DelegatedAgentExchangeRequest("https://as.example.test","client",null,
                List.of("https://api.example.test/"),List.of(),List.of("read"),new byte[]{1},new byte[]{2},h("actor-nonce"),new ValidatedDpopProof(jkt()),now);
        return new Fixture(request,subject,actor);
    }

    DelegatedAgentExchangeService service(Fixture f,AssertionReplayStore replay,CapabilityMapper mapper){
        return new DelegatedAgentExchangeService(b->f.subject(),r->f.actor(),x->x,mapper,replay,300);
    }

    @Test void successfulExchangeConsumesAssertionAndClipsExpiry(){
        Fixture f=fixture();AtomicBoolean consumed=new AtomicBoolean();
        var s=service(f,id->consumed.compareAndSet(false,true),(sub,target,scope)->target.equals("https://api.example.test/")&&scope.equals("read"));
        var d=s.exchange(f.request());assertTrue(consumed.get());assertEquals(f.request().now()+180,d.expiresAt());
        assertEquals(jkt(),d.dpopJkt());assertEquals("read",d.scopes().getFirst());
    }

    @Test void replayIsRejected(){
        Fixture f=fixture();var s=service(f,id->false,(sub,target,scope)->true);
        ProfileException e=assertThrows(ProfileException.class,()->s.exchange(f.request()));
        assertEquals(ProfileError.ASSERTION_REPLAY,e.error());
    }

    @Test void unauthorizedPairIsRejectedBeforeReplayConsumption(){
        Fixture f=fixture();AtomicBoolean consumed=new AtomicBoolean();
        var s=service(f,id->{consumed.set(true);return true;},(sub,target,scope)->false);
        ProfileException e=assertThrows(ProfileException.class,()->s.exchange(f.request()));
        assertEquals(ProfileError.TARGET_SCOPE_PAIR_NOT_AUTHORIZED,e.error());assertFalse(consumed.get());
    }

    @Test void dpopSubstitutionIsRejected(){
        Fixture f=fixture();
        var bad=new DelegatedAgentExchangeRequest(f.request().authorizationServer(),f.request().clientId(),null,
                f.request().resources(),f.request().audiences(),f.request().scopes(),new byte[]{1},new byte[]{2},f.request().actorNonce(),
                new ValidatedDpopProof(Base64.getUrlEncoder().withoutPadding().encodeToString(h("other dpop"))),f.request().now());
        var s=service(f,id->true,(sub,target,scope)->true);
        ProfileException e=assertThrows(ProfileException.class,()->s.exchange(bad));
        assertEquals(ProfileError.ASSERTION_CONTEXT_BINDING_MISMATCH,e.error());
    }
}
