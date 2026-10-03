package org.openidentity.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;import java.util.HexFormat;

class VerifiedIdentityTransitionTest {
 @Test void defensiveCopiesAndExactNextSequence(){
  byte[] id=new byte[32],ph=new byte[34],next=new byte[34],state={1,2,3};ph[0]=next[0]=0x12;ph[1]=next[1]=0x20;
  var t=new VerifiedIdentityTransition(id,1,ph,2,state,next,2,3,1);
  id[0]=9;ph[2]=9;state[0]=9;next[2]=9;
  assertEquals(0,t.identity()[0]);assertEquals(0,t.predecessorStateHash()[2]);assertEquals(1,t.successorStateBytes()[0]);assertEquals(0,t.successorStateHash()[2]);
  assertThrows(IllegalArgumentException.class,()->new VerifiedIdentityTransition(new byte[32],1,new byte[34],3,new byte[]{1},new byte[34],2,3,1));
 }
 @Test void malformedCommitmentsRejected(){
  assertThrows(IllegalArgumentException.class,()->new VerifiedIdentityTransition(new byte[31],1,new byte[34],2,new byte[]{1},new byte[34],2,3,1));
  assertThrows(IllegalArgumentException.class,()->new VerifiedIdentityTransition(new byte[32],1,new byte[32],2,new byte[]{1},new byte[34],2,3,1));
 }
 @Test void v304CanonicalCommitmentsMatchFrozenTransition(){
  var h=HexFormat.of();
  byte[] previous=h.parseHex("a50102025820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0301040105a201010281a20150000102030405060708090a0b0c0d0e0f02a4010103272006215820e17c1ebe48de2b7f7a34cb50662d2ff458a11fa909debf300a70cecda9392f55");
  byte[] successor=h.parseHex("a70103025820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0302040105a201010281a20150000102030405060708090a0b0c0d0e0f02a4010103272006215820e17c1ebe48de2b7f7a34cb50662d2ff458a11fa909debf300a70cecda9392f5508a2010002a201010281a20150101112131415161718191a1b1c1d1e1f02a4010103272006215820753fd15f9c77d97898e4385827d759ca52650c8594aa3f9e5051a0a89db31c2b09a10100");
  var p=IdentityStateCommitment.parse(previous);var s=IdentityStateCommitment.parse(successor);
  assertEquals(2,p.stateVersion());assertEquals(1,p.sequence());assertEquals(3,s.stateVersion());assertEquals(2,s.sequence());
  assertEquals("122069bfcfca0c3736a7dc068134de2a0937461da7f7e07f752f208c34d935adbf92",h.formatHex(p.stateHash()));
  assertEquals("12200981d3498020d96bb434d18e10cea3686bf2011034ec72134847a31ba22372bc",h.formatHex(s.stateHash()));
  assertArrayEquals(p.identity(),s.identity());
 }

}
