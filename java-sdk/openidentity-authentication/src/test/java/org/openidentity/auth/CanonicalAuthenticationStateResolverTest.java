package org.openidentity.auth;

import org.junit.jupiter.api.Test;
import org.openidentity.core.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class CanonicalAuthenticationStateResolverTest {
 @Test void derivesExactOi015StateFromCanonicalIdentityState(){
  byte[] id=new byte[32],hash=new byte[34],method={1},pk=new byte[32];hash[0]=0x12;hash[1]=0x20;
  var canonical=new CanonicalIdentityState(id,hash,true,new CanonicalAuthenticationAuthority(7,1,List.of(new CanonicalAuthenticationMethod(method,pk))));
  var resolved=new CanonicalAuthenticationStateResolver(identity->canonical).resolve(id);
  assertArrayEquals(id,resolved.identity());assertArrayEquals(hash,resolved.stateHash());assertTrue(resolved.active());
  assertEquals(7,resolved.policy().generation());assertEquals(1,resolved.policy().threshold());assertArrayEquals(method,resolved.policy().methods().get(0).methodId());assertArrayEquals(pk,resolved.policy().methods().get(0).ed25519PublicKey());
 }
 @Test void missingCanonicalIdentityRemainsUnavailable(){assertNull(new CanonicalAuthenticationStateResolver(identity->null).resolve(new byte[32]));}
}
