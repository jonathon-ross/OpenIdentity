package org.openidentity.bootstrap;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.junit.jupiter.api.*;import org.junit.jupiter.api.io.TempDir;
import org.openidentity.core.*;
import java.nio.file.*;import java.security.SecureRandom;import java.util.HexFormat;
import static org.junit.jupiter.api.Assertions.*;

final class ImportCanonicalIdentityTest {
 @TempDir Path dir;
 @Test void importsPublicStateAndSeparatesVerifiedPrivateSeed()throws Exception{
  var h=HexFormat.of();byte[] id=new byte[32],hash=new byte[34],method={1};hash[0]=0x12;hash[1]=0x20;byte[] seed=new byte[32];new SecureRandom().nextBytes(seed);byte[] pk=new Ed25519PrivateKeyParameters(seed,0).generatePublicKey().getEncoded();Path states=dir.resolve("states"),auth=dir.resolve("auth.key");
  ImportCanonicalIdentity.main(new String[]{"--identity",h.formatHex(id),"--state-hash",h.formatHex(hash),"--method-id",h.formatHex(method),"--public-key",h.formatHex(pk),"--state-dir",states.toString(),"--private-seed",h.formatHex(seed),"--authenticator-file",auth.toString()});
  var s=new FileCanonicalIdentityStateRepository(states).resolve(id);assertNotNull(s);assertArrayEquals(pk,s.authenticationAuthority().methods().get(0).ed25519PublicKey());String publicFile=Files.readString(Files.list(states).findFirst().orElseThrow());assertFalse(publicFile.contains(h.formatHex(seed)));assertTrue(Files.readString(auth).contains(h.formatHex(seed)));
 }
 @Test void rejectsPrivateSeedThatDoesNotMatchPublicKey(){
  byte[] id=new byte[32],hash=new byte[34],pk=new byte[32],seed=new byte[32];hash[0]=0x12;hash[1]=0x20;seed[0]=1;var h=HexFormat.of();
  assertThrows(IllegalArgumentException.class,()->ImportCanonicalIdentity.main(new String[]{"--identity",h.formatHex(id),"--state-hash",h.formatHex(hash),"--method-id","01","--public-key",h.formatHex(pk),"--state-dir",dir.resolve("s").toString(),"--private-seed",h.formatHex(seed),"--authenticator-file",dir.resolve("a").toString()}));
 }
}
