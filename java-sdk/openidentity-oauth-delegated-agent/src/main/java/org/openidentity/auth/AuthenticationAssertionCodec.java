package org.openidentity.auth;

import org.openidentity.cbor.DeterministicCborWriter;
import java.util.*;

public final class AuthenticationAssertionCodec {
 private AuthenticationAssertionCodec(){}
 public static byte[] signingBytes(AuthenticationAssertion a,byte[] methodId){
  DeterministicCborWriter w=new DeterministicCborWriter();w.writeArrayHeader(4);
  w.writeTextString("OpenIdentity Authentication Assertion");w.writeUnsigned(1);w.writeByteString(a.exactAssertionBytes());w.writeByteString(methodId);return w.toByteArray();
 }
}
