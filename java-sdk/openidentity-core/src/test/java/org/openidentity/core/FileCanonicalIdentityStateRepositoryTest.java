package org.openidentity.core;

import org.junit.jupiter.api.Test;import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class FileCanonicalIdentityStateRepositoryTest {
 @TempDir Path dir;
 private static CanonicalIdentityState state(){
  byte[] id=new byte[32],hash=new byte[34],pk=new byte[32];id[31]=1;hash[0]=0x12;hash[1]=0x20;pk[0]=7;
  return new CanonicalIdentityState(id,hash,true,new CanonicalAuthenticationAuthority(4,1,List.of(new CanonicalAuthenticationMethod(new byte[]{1,2},pk))));
 }
 @Test void roundTripsCanonicalPublicState()throws Exception{
  var r=new FileCanonicalIdentityStateRepository(dir);var s=state();r.save(s);var x=r.resolve(s.identity());
  assertArrayEquals(s.identity(),x.identity());assertArrayEquals(s.stateHash(),x.stateHash());assertEquals(4,x.authenticationAuthority().generation());assertEquals(1,x.authenticationAuthority().threshold());assertArrayEquals(s.authenticationAuthority().methods().get(0).ed25519PublicKey(),x.authenticationAuthority().methods().get(0).ed25519PublicKey());
  String persisted=Files.readString(Files.list(dir).findFirst().orElseThrow());assertFalse(persisted.toLowerCase(Locale.ROOT).contains("private"));assertFalse(persisted.toLowerCase(Locale.ROOT).contains("secret"));
 }
 @Test void rejectsUnknownOrCorruptFields()throws Exception{
  var r=new FileCanonicalIdentityStateRepository(dir);var s=state();r.save(s);Path p=Files.list(dir).findFirst().orElseThrow();Files.writeString(p,Files.readString(p)+"unexpected=value\n");
  assertThrows(IllegalArgumentException.class,()->r.resolve(s.identity()));
 }
 @Test void missingIdentityReturnsNull(){assertNull(new FileCanonicalIdentityStateRepository(dir).resolve(new byte[32]));}
 @Test void saveReplacesStateAtomicallyFromReaderPerspective(){
  var r=new FileCanonicalIdentityStateRepository(dir);var s=state();r.save(s);
  var newer=new CanonicalIdentityState(s.identity(),s.stateHash(),false,new CanonicalAuthenticationAuthority(5,1,s.authenticationAuthority().methods()));r.save(newer);
  var x=r.resolve(s.identity());assertFalse(x.active());assertEquals(5,x.authenticationAuthority().generation());
 }
}
