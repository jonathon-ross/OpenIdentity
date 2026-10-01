package org.openidentity.bootstrap;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;import org.bouncycastle.crypto.signers.Ed25519Signer;import org.junit.jupiter.api.Test;
import java.security.*;import java.util.*;import static org.junit.jupiter.api.Assertions.*;

final class CreateIdentityV2Test {
 @Test void createProducesV3StateAndDistinctControllerAuthenticationProofDomains()throws Exception{
  var c=CreateIdentityV2.create(new SecureRandom());assertEquals(32,c.identity().length);assertEquals(34,c.stateHash().length);assertEquals(64,c.controllerSignature().length);assertEquals(64,c.authenticationPop().length);assertFalse(Arrays.equals(c.controllerPublicKey(),c.authenticationPublicKey()));
  assertTrue(verify(c.controllerPublicKey(),CreateIdentityV2.operationSigning(c.operationBytes()),c.controllerSignature()));
  assertTrue(verify(c.authenticationPublicKey(),CreateIdentityV2.authenticationPopSigning(c.operationBytes(),c.authenticationMethodId()),c.authenticationPop()));
  assertFalse(verify(c.authenticationPublicKey(),CreateIdentityV2.operationSigning(c.operationBytes()),c.authenticationPop()));
  assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(c.stateBytes()),Arrays.copyOfRange(c.stateHash(),2,34));
 }
 private static boolean verify(byte[] pk,byte[] input,byte[] sig){Ed25519Signer v=new Ed25519Signer();v.init(false,new Ed25519PublicKeyParameters(pk,0));v.update(input,0,input.length);return v.verifySignature(sig);}
}
