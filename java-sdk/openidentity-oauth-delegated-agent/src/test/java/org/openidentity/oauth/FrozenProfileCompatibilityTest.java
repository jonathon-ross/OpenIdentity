package org.openidentity.oauth;

import org.junit.jupiter.api.Test;
import org.openidentity.crypto.Sha256Multihash;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class FrozenProfileCompatibilityTest {
    static byte[] sha(String s)throws Exception{return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));}
    static byte[] seq(int start,int n){byte[] b=new byte[n];for(int i=0;i<n;i++)b[i]=(byte)(start+i);return b;}

    @Test void tx01ContextIsDeterministicAndBound()throws Exception{
        byte[] eid=Sha256Multihash.digest("OpenIdentity OAuth TX01 delegation evidence".getBytes(StandardCharsets.UTF_8));
        String jkt=Base64.getUrlEncoder().withoutPadding().encodeToString(sha("OpenIdentity OAuth TX01 DPoP public JWK"));
        var c=new OAuthTokenExchangeContextV1("https://as.example.test","agent-client-016",
                "urn:ietf:params:oauth:token-type:access_token",
                List.of("https://api.example.test/v2","https://api.example.test/v1"),
                List.of("records-service","audit-service"),List.of("records.write","records.read"),eid,jkt);
        byte[] a=OAuthTokenExchangeContextV1Encoder.encode(c),b=OAuthTokenExchangeContextV1Encoder.encode(c);
        assertArrayEquals(a,b);assertArrayEquals(Sha256Multihash.digest(a),OAuthTokenExchangeContextV1Encoder.contextHash(c));
        assertTrue(a.length>0);
    }

    @Test void tx05AllowsAbsentRequestedTypeAndEmptyCollections()throws Exception{
        byte[] eid=Sha256Multihash.digest("OpenIdentity OAuth TX05 evidence".getBytes(StandardCharsets.UTF_8));
        String jkt=Base64.getUrlEncoder().withoutPadding().encodeToString(sha("OpenIdentity OAuth TX05 DPoP"));
        var c=new OAuthTokenExchangeContextV1("urn:example:authorization-server","c",null,List.of(),List.of(),List.of(),eid,jkt);
        assertNotNull(OAuthTokenExchangeContextV1Encoder.encode(c));
    }

    @Test void px01DecisionClipsLifetimeAndProjectsClaims()throws Exception{
        long now=2004000000L;byte[] root=seq(0,32),actor=seq(32,32),assertionId=Sha256Multihash.digest("px01 assertion".getBytes(StandardCharsets.UTF_8));
        byte[] eid=Sha256Multihash.digest("px01 evidence".getBytes(StandardCharsets.UTF_8));
        String jkt=Base64.getUrlEncoder().withoutPadding().encodeToString(sha("OpenIdentity PX01 DPoP key"));
        var context=new OAuthTokenExchangeContextV1("https://as.example.test","agent-client-016",null,
                List.of("https://api.example.test/"),List.of(),List.of("records.read","records.write"),eid,jkt);
        var subject=new VerifiedDelegatedSubject(root,actor,assertionId,eid,now+180,List.of());
        var auth=new VerifiedAuthenticationAssertion(actor,assertionId,OAuthTokenExchangeContextV1Encoder.contextHash(context),DelegatedAgentProfileVerifier.PURPOSE);
        CapabilityMapper mapper=(s,t,scope)->t.equals("https://api.example.test/")&&(scope.equals("records.read")||scope.equals("records.write"));
        var d=DelegatedAgentProfileVerifier.authorize(subject,auth,context,new ValidatedDpopProof(jkt),
                List.of("https://api.example.test/"),List.of("records.read","records.write"),mapper,now,300);
        assertEquals(now+180,d.expiresAt());assertArrayEquals(root,d.subjectIdentity());assertArrayEquals(actor,d.actorIdentity());
        var claims=JwtProjection.claims(d);assertEquals(HexFormat.of().formatHex(root),claims.get("sub"));assertEquals(now+180,claims.get("exp"));
        assertFalse(claims.containsKey("refresh_token"));
    }
}
