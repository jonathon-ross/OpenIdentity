package org.openidentity.ad;
import org.junit.jupiter.api.Test;import java.util.*;import static org.junit.jupiter.api.Assertions.*;
final class ExternalAdPrincipalBridgeTest{
 @Test void bridgePreservesOnlyVerifiedBindingInputs(){
  byte[] d=new byte[16],g=new byte[16];g[15]=9;var v=new VerifiedAdPrincipal(d,g,"svc",1,true,true,true,Map.of("upn","ignored@example.test"));
  var p=ExternalAdPrincipalBridge.registryPrincipal(v);assertArrayEquals(d,p.directoryId());assertArrayEquals(g,p.objectGuid());assertEquals("svc",p.serviceId());assertEquals(1,p.mechanism());assertTrue(p.channelTrusted());assertTrue(p.accountUsable());assertTrue(p.assuranceSufficient());
 }
}