package org.openidentity.bootstrap;

import org.junit.jupiter.api.*;import org.junit.jupiter.api.io.TempDir;import org.openidentity.core.*;
import java.nio.file.*;import java.util.*;import static org.junit.jupiter.api.Assertions.*;

final class CreateCanonicalIdentityTest {
 @TempDir Path dir;
 @Test void createPersistsPublicAuthenticationStateAndSeparatesSecrets()throws Exception{
  Path states=dir.resolve("state"),secrets=dir.resolve("secrets");CreateCanonicalIdentity.main(new String[]{"--state-dir",states.toString(),"--secret-dir",secrets.toString()});
  Path publicFile=Files.list(states).findFirst().orElseThrow(),authFile=Files.list(secrets).filter(p->p.getFileName().toString().endsWith(".authentication.key")).findFirst().orElseThrow(),controllerFile=Files.list(secrets).filter(p->p.getFileName().toString().endsWith(".controller.key")).findFirst().orElseThrow();
  String name=publicFile.getFileName().toString();byte[] id=HexFormat.of().parseHex(name.substring(0,name.indexOf('.')));var state=new FileCanonicalIdentityStateRepository(states).resolve(id);
  assertNotNull(state);assertTrue(state.active());assertEquals(0,state.authenticationAuthority().generation());assertEquals(1,state.authenticationAuthority().threshold());
  String pub=Files.readString(publicFile),auth=Files.readString(authFile),controller=Files.readString(controllerFile);assertFalse(pub.contains("ed25519Seed"));assertTrue(auth.contains("purpose=authentication"));assertTrue(controller.contains("purpose=controller"));assertNotEquals(auth,controller);
  String authPk=field(auth,"ed25519PublicKey");assertEquals(HexFormat.of().formatHex(state.authenticationAuthority().methods().get(0).ed25519PublicKey()),authPk);
 }
 @Test void refusesSecretOverwrite()throws Exception{
  Path states=dir.resolve("state"),secrets=dir.resolve("secrets");CreateCanonicalIdentity.main(new String[]{"--state-dir",states.toString(),"--secret-dir",secrets.toString()});
  assertEquals(2,Files.list(secrets).count());
 }
 private static String field(String s,String k){return Arrays.stream(s.split("\\R")).filter(x->x.startsWith(k+"=")).map(x->x.substring(k.length()+1)).findFirst().orElseThrow();}
}
