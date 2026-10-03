package org.openidentity.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

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
}
