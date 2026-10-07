package org.openidentity.protocol.v2;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.openidentity.cbor.*;
import org.openidentity.core.*;
import java.security.MessageDigest;
import java.util.*;

public final class ProtocolV2TransitionVerifier {
 private static final long CREATE=1,ROTATE_CONTROLLER=2,RECOVER=3,DEACTIVATE=4,SET_AUTHENTICATION_POLICY=6,SET_DELEGATION_POLICY=7,RESET_AUTHENTICATION=8,RESET_DELEGATIONS=9;
 private ProtocolV2TransitionVerifier(){}

 public static VerifiedIdentityTransition verifyAndApply(byte[] predecessorStateBytes,byte[] signedOperationBytes){
  State predecessor=parseState(predecessorStateBytes);
  Signed signed=parseSigned(signedOperationBytes);
  Operation op=parseOperation(signed.operationBytes);
  require(op.protocolVersion==2&&(op.type==SET_AUTHENTICATION_POLICY||op.type==ROTATE_CONTROLLER||op.type==RESET_AUTHENTICATION||op.type==SET_DELEGATION_POLICY||op.type==RESET_DELEGATIONS||op.type==RECOVER||op.type==DEACTIVATE),"unsupported Protocol v2 operation");
  require(MessageDigest.isEqual(op.identity,predecessor.identity),"operation identity mismatch");
  require(predecessor.sequence!=Long.MAX_VALUE&&op.sequence==predecessor.sequence+1,"operation sequence mismatch");
  require(MessageDigest.isEqual(op.previousStateHash,IdentityStateCommitment.sha256Multihash(predecessorStateBytes)),"previous StateHash mismatch");
  require(predecessor.status==1||op.type==RECOVER,"operation not permitted while DEACTIVATED");
  Policy controller=parsePolicy(predecessor.controllerPolicy);
  if(op.type!=RECOVER)require(verifyThreshold(controller,signed.controllerProofs,signing("OpenIdentity Operation",signed.operationBytes,null)),"controller authorization invalid");
  byte[] successor;
  if(op.type==RECOVER){
   require(signed.controllerProofs.isEmpty(),"RECOVER forbids ordinary controller authorization");require(signed.authenticationProofs.isEmpty()&&signed.delegationProofs.isEmpty(),"RECOVER forbids derived-authority proofs");
   require(predecessor.recovery!=null&&predecessor.recovery.length==34,"recovery unavailable");RecoveryPayload rp=parseRecoveryPayload(op.payload);
   Policy newController=parsePolicy(rp.controllerPolicy);require(verifyPop(newController,signed.controllerPops,signed.operationBytes,"OpenIdentity Controller Proof"),"recovered controller PoP invalid");
   require(MessageDigest.isEqual(predecessor.recovery,IdentityStateCommitment.sha256Multihash(rp.recoveryPolicy)),"recovery commitment mismatch");
   Policy recoveryPolicy=parseRecoveryPolicy(rp.recoveryPolicy);require(verifyRecoveryThreshold(recoveryPolicy,signed.recoveryProofs,signed.operationBytes),"recovery authorization invalid");
   byte[] assertion;if(rp.assertionDisposition==1){require(rp.assertionPolicy==null&&signed.assertionProofs.isEmpty(),"invalid assertion preserve");assertion=predecessor.assertion;}
   else if(rp.assertionDisposition==2){require(predecessor.assertion!=null&&rp.assertionPolicy==null&&signed.assertionProofs.isEmpty(),"invalid assertion removal");assertion=null;}
   else if(rp.assertionDisposition==3){require(predecessor.assertion!=null&&rp.assertionPolicy!=null,"invalid assertion replacement");require(verifyPop(parsePolicy(rp.assertionPolicy),signed.assertionProofs,signed.operationBytes,"OpenIdentity Assertion Proof"),"assertion PoP invalid");assertion=rp.assertionPolicy;}
   else throw new IllegalArgumentException("invalid assertion disposition");
   long ag=predecessor.version==3?predecessor.authentication.generation:0,dg=predecessor.version==3?predecessor.delegation.generation:0;require(ag!=Long.MAX_VALUE&&dg!=Long.MAX_VALUE,"recovery generation overflow");
   successor=encodeRecoveryState(predecessor,op.sequence,rp.controllerPolicy,rp.newRecoveryCommitment,assertion,ag+1,dg+1);
  }else if(op.type==DEACTIVATE){
   require(predecessor.status==1,"DEACTIVATE requires ACTIVE");require(signed.controllerPops.isEmpty()&&signed.recoveryProofs.isEmpty()&&signed.authenticationProofs.isEmpty()&&signed.assertionProofs.isEmpty()&&signed.delegationProofs.isEmpty(),"unexpected DEACTIVATE proofs");requireEmptyPayload(op.payload);
   successor=encodeStatusState(predecessor,op.sequence,2);
  }else if(op.type==ROTATE_CONTROLLER){
   require(signed.authenticationProofs.isEmpty()&&signed.assertionProofs.isEmpty()&&signed.delegationProofs.isEmpty(),"unexpected derived-authority proofs");
   byte[] nextController=parseSinglePolicyPayload(op.payload,"controller policy payload");Policy proposed=parsePolicy(nextController);
   require(verifyPop(proposed,signed.controllerPops,signed.operationBytes,"OpenIdentity Controller Proof"),"controller proof-of-possession invalid");
   successor=encodeControllerRotationState(predecessor,op.sequence,nextController);
  }else if(op.type==RESET_DELEGATIONS){
   require(predecessor.version==3,"RESET_DELEGATIONS requires v3");require(signed.controllerPops.isEmpty()&&signed.authenticationProofs.isEmpty()&&signed.assertionProofs.isEmpty()&&signed.delegationProofs.isEmpty(),"unexpected RESET proofs");
   requireEmptyPayload(op.payload);require(predecessor.delegation.generation!=Long.MAX_VALUE,"delegation generation overflow");
   successor=encodePreservingDelegationState(predecessor,op.sequence,new Authority(predecessor.delegation.generation+1,predecessor.delegation.policy));
  }else if(op.type==SET_DELEGATION_POLICY){
   require(signed.controllerPops.isEmpty()&&signed.authenticationProofs.isEmpty()&&signed.assertionProofs.isEmpty(),"unexpected non-delegation proofs");
   Payload payload=parsePayload(op.payload);Authority current=predecessor.delegation;long generation=current.generation;byte[] next=payload.authenticationPolicy;
   if(current.policy==null){require(next!=null,"cannot remove absent delegation policy");require(payload.disposition==null,"disposition forbidden on initial install");}
   else if(next==null){require(payload.disposition==null,"disposition forbidden on removal");require(generation!=Long.MAX_VALUE,"delegation generation overflow");generation++;}
   else {require(!Arrays.equals(current.policy,next),"no-op delegation policy replacement");require(payload.disposition!=null,"missing delegation disposition");require(payload.disposition==1||payload.disposition==2,"invalid delegation disposition");if(payload.disposition==1){require(generation!=Long.MAX_VALUE,"delegation generation overflow");generation++;}}
   if(next!=null)require(verifyPop(parsePolicy(next),signed.delegationProofs,signed.operationBytes,"OpenIdentity Delegation Proof"),"delegation proof-of-possession invalid");else require(signed.delegationProofs.isEmpty(),"proofs forbidden on removal");
   successor=encodePreservingDelegationState(predecessor,op.sequence,new Authority(generation,next));
  }else if(op.type==RESET_AUTHENTICATION){
   require(predecessor.version==3,"RESET_AUTHENTICATION requires v3");require(signed.controllerPops.isEmpty()&&signed.authenticationProofs.isEmpty()&&signed.assertionProofs.isEmpty()&&signed.delegationProofs.isEmpty(),"unexpected RESET proofs");
   requireEmptyPayload(op.payload);require(predecessor.authentication.generation!=Long.MAX_VALUE,"authentication generation overflow");
   successor=encodePreservingState(predecessor,op.sequence,new Authority(predecessor.authentication.generation+1,predecessor.authentication.policy));
  }else{
   require(signed.controllerPops.isEmpty(),"unexpected controller PoP");
   Payload payload=parsePayload(op.payload);Authority current=predecessor.authentication;long generation=current.generation;byte[] next=payload.authenticationPolicy;
   if(current.policy==null){require(next!=null,"cannot remove absent authentication policy");require(payload.disposition==null,"disposition forbidden on initial install");}
   else if(next==null){require(payload.disposition==null,"disposition forbidden on removal");require(generation!=Long.MAX_VALUE,"authentication generation overflow");generation++;}
   else {require(!Arrays.equals(current.policy,next),"no-op authentication policy replacement");require(payload.disposition!=null,"missing authentication disposition");require(payload.disposition==1||payload.disposition==2,"invalid authentication disposition");if(payload.disposition==1){require(generation!=Long.MAX_VALUE,"authentication generation overflow");generation++;}}
   if(next!=null)require(verifyPop(parsePolicy(next),signed.authenticationProofs,signed.operationBytes,"OpenIdentity Authentication Proof"),"authentication proof-of-possession invalid");else require(signed.authenticationProofs.isEmpty(),"proofs forbidden on removal");
   successor=encodePreservingState(predecessor,op.sequence,new Authority(generation,next));
  }
  var pc=IdentityStateCommitment.parse(predecessorStateBytes);var sc=IdentityStateCommitment.parse(successor);
  return new VerifiedIdentityTransition(pc.identity(),pc.sequence(),pc.stateHash(),sc.sequence(),successor,sc.stateHash(),2,sc.stateVersion(),sc.status());
 }

 public static VerifiedIdentityCreation verifyCreate(byte[] signedOperationBytes){
  Signed signed=parseSigned(signedOperationBytes);Operation op=parseOperation(signed.operationBytes);
  require(op.protocolVersion==2&&op.type==CREATE,"not Protocol v2 CREATE");require(op.sequence==1,"CREATE sequence");require(op.previousStateHash==null,"CREATE predecessor must be null");
  require(signed.controllerPops.isEmpty(),"CREATE forbids controller PoP");
  CreatePayload p=parseCreatePayload(op.payload);Policy controller=parsePolicy(p.controllerPolicy);
  require(verifyThreshold(controller,signed.controllerProofs,signing("OpenIdentity Operation",signed.operationBytes,null)),"CREATE controller authorization invalid");
  if(p.authenticationPolicy==null)require(signed.authenticationProofs.isEmpty(),"unexpected authentication proofs");else require(verifyPop(parsePolicy(p.authenticationPolicy),signed.authenticationProofs,signed.operationBytes,"OpenIdentity Authentication Proof"),"authentication PoP invalid");
  if(p.assertionPolicy==null)require(signed.assertionProofs.isEmpty(),"unexpected assertion proofs");else require(verifyPop(parsePolicy(p.assertionPolicy),signed.assertionProofs,signed.operationBytes,"OpenIdentity Assertion Proof"),"assertion PoP invalid");
  if(p.delegationPolicy==null)require(signed.delegationProofs.isEmpty(),"unexpected delegation proofs");else require(verifyPop(parsePolicy(p.delegationPolicy),signed.delegationProofs,signed.operationBytes,"OpenIdentity Delegation Proof"),"delegation PoP invalid");
  byte[] state=encodeCreateState(op.identity,p);var sc=IdentityStateCommitment.parse(state);
  return new VerifiedIdentityCreation(sc.identity(),state,sc.stateHash(),2,3,sc.sequence(),sc.status());
 }

 private record State(int version,byte[] identity,long sequence,int status,byte[] controllerPolicy,byte[] recovery,byte[] assertion,Authority authentication,Authority delegation){}
 private record Authority(long generation,byte[] policy){}
 private record Operation(long protocolVersion,long type,byte[] identity,long sequence,byte[] previousStateHash,byte[] payload){}
 private record Signed(byte[] operationBytes,List<Proof> controllerProofs,List<Proof> controllerPops,List<Proof> recoveryProofs,List<Proof> authenticationProofs,List<Proof> assertionProofs,List<Proof> delegationProofs){}
 private record Proof(byte[] methodId,byte[] signature){}
 private record Method(byte[] id,byte[] publicKey){}
 private record Policy(long threshold,List<Method> methods){}
 private record Payload(byte[] authenticationPolicy,Long disposition){}
 private record CreatePayload(byte[] controllerPolicy,byte[] recoveryCommitment,byte[] assertionPolicy,byte[] authenticationPolicy,byte[] delegationPolicy){}
 private record RecoveryPayload(byte[] controllerPolicy,byte[] recoveryPolicy,byte[] newRecoveryCommitment,long assertionDisposition,byte[] assertionPolicy){}

 private static State parseState(byte[] bytes){
  StrictCborReader r=new StrictCborReader(bytes);long n=r.readMapHeader(),prev=0,version=-1,seq=-1,status=-1;byte[] id=null,cp=null,recovery=null,assertion=null;Authority auth=null,delegation=null;
  for(long i=0;i<n;i++){long k=r.readUnsigned();require(k>prev,"noncanonical State labels");prev=k;
   if(k==1)version=r.readUnsigned();else if(k==2)id=r.readByteString();else if(k==3)seq=r.readUnsigned();else if(k==4)status=r.readUnsigned();
   else if(k==5)cp=r.readEncoded();else if(k==6)recovery=r.readByteString();else if(k==7)assertion=r.readEncoded();else if(k==8)auth=parseAuthority(r.readEncoded());else if(k==9)delegation=parseAuthority(r.readEncoded());else r.skipValue();
  }
  require(r.done()&&(version==1||version==2||version==3)&&id!=null&&id.length==32&&cp!=null,"invalid predecessor StateBytes");
  if(version<3){require(auth==null&&delegation==null,"derived authority in legacy state");auth=new Authority(0,null);delegation=new Authority(0,null);}
  else require(auth!=null&&delegation!=null,"missing v3 authority");
  return new State(Math.toIntExact(version),id,seq,Math.toIntExact(status),cp,recovery,assertion,auth,delegation);
 }
 private static Authority parseAuthority(byte[] bytes){StrictCborReader r=new StrictCborReader(bytes);long n=r.readMapHeader();require(n==1||n==2,"authority");require(r.readUnsigned()==1,"authority generation");long g=r.readUnsigned();byte[] p=null;if(n==2){require(r.readUnsigned()==2,"authority policy");p=r.readEncoded();}require(r.done(),"authority trailing");return new Authority(g,p);}
 private static Signed parseSigned(byte[] bytes){
  StrictCborReader r=new StrictCborReader(bytes);require(r.readMapHeader()>=1,"signed operation");byte[] op=null;List<Proof> controller=List.of(),controllerPops=List.of(),recovery=List.of(),auth=List.of(),assertion=List.of(),delegation=List.of();long prev=0;
  while(!r.done()){long k=r.readUnsigned();require(k>prev,"noncanonical signed labels");prev=k;if(k==1)op=r.readEncoded();else if(k==2)controller=proofs(r);else if(k==3)controllerPops=proofs(r);else if(k==4)recovery=proofs(r);else if(k==5)auth=proofs(r);else if(k==6)assertion=proofs(r);else if(k==7)delegation=proofs(r);else r.skipValue();}
  require(op!=null,"missing operation");return new Signed(op,controller,controllerPops,recovery,auth,assertion,delegation);
 }
 private static List<Proof> proofs(StrictCborReader r){long n=r.readArrayHeader();List<Proof> out=new ArrayList<>();for(long i=0;i<n;i++){require(r.readMapHeader()==2,"proof");require(r.readUnsigned()==1,"proof method");byte[] id=r.readByteString();require(r.readUnsigned()==2,"proof signature");out.add(new Proof(id,r.readByteString()));}return List.copyOf(out);}
 private static Operation parseOperation(byte[] bytes){
  StrictCborReader r=new StrictCborReader(bytes);require(r.readMapHeader()==6,"operation fields");long pv=-1,type=-1,seq=-1,prevLabel=0;byte[] id=null,ph=null,payload=null;
  for(int i=0;i<6;i++){long k=r.readUnsigned();require(k>prevLabel,"operation labels");prevLabel=k;if(k==1)pv=r.readUnsigned();else if(k==2)type=r.readUnsigned();else if(k==3)id=r.readByteString();else if(k==4)seq=r.readUnsigned();else if(k==5){if(r.peekByte()==0xf6){r.readNull();ph=null;}else ph=r.readByteString();}else if(k==6)payload=r.readEncoded();else throw new IllegalArgumentException("operation label");}
  require(r.done()&&id!=null&&payload!=null,"operation");return new Operation(pv,type,id,seq,ph,payload);
 }


 private static RecoveryPayload parseRecoveryPayload(byte[] bytes){StrictCborReader r=new StrictCborReader(bytes);long n=r.readMapHeader();require(n==4||n==5,"recovery payload shape");require(r.readUnsigned()==1,"recovery controller");byte[] cp=r.readEncoded();require(r.readUnsigned()==2,"recovery policy");byte[] rp=r.readEncoded();require(r.readUnsigned()==3,"new recovery commitment");byte[] rc=r.readByteString();require(rc.length==34&&rc[0]==0x12&&rc[1]==0x20,"new recovery commitment must be SHA2-256 Multihash");require(r.readUnsigned()==4,"assertion disposition");long d=r.readUnsigned();byte[] ap=null;if(n==5){require(r.readUnsigned()==5,"replacement assertion");ap=r.readEncoded();}require(r.done(),"recovery payload trailing");return new RecoveryPayload(cp,rp,rc,d,ap);}
 private static Policy parseRecoveryPolicy(byte[] bytes){
  StrictCborReader r=new StrictCborReader(bytes);long fields=r.readMapHeader();
  require(fields==3||fields==4,"recovery policy");
  require(r.readUnsigned()==1&&r.readUnsigned()==1,"recovery policy version");
  require(r.readUnsigned()==2,"recovery policy type");long type=r.readUnsigned();
  long threshold;
  if(type==1){require(fields==3,"recovery SINGLE shape");threshold=1;require(r.readUnsigned()==3,"recovery methods");}
  else if(type==2){require(fields==4,"recovery THRESHOLD shape");require(r.readUnsigned()==3,"recovery threshold");threshold=r.readUnsigned();require(r.readUnsigned()==4,"recovery methods");}
  else throw new IllegalArgumentException("recovery policy type");
  long n=r.readArrayHeader();List<Method> ms=new ArrayList<>();
  for(long i=0;i<n;i++){byte[] m=r.readEncoded();Policy one=parsePolicy(singleMethodPolicy(m));ms.add(one.methods.get(0));}
  require(r.done()&&threshold>0&&threshold<=ms.size(),"recovery threshold");
  return new Policy(threshold,List.copyOf(ms));
 }
 private static byte[] singleMethodPolicy(byte[] method){var w=new DeterministicCborWriter();w.writeMapHeader(2);w.writeUnsigned(1);w.writeUnsigned(1);w.writeUnsigned(2);w.writeArrayHeader(1);w.writeEncoded(method);return w.toByteArray();}
 private static byte[] encodeRecoveryState(State p,long sequence,byte[] controller,byte[] recovery,byte[] assertion,long authGeneration,long delegationGeneration){int n=8+(assertion==null?0:1);var w=new DeterministicCborWriter();w.writeMapHeader(n);w.writeUnsigned(1);w.writeUnsigned(3);w.writeUnsigned(2);w.writeByteString(p.identity);w.writeUnsigned(3);w.writeUnsigned(sequence);w.writeUnsigned(4);w.writeUnsigned(1);w.writeUnsigned(5);w.writeEncoded(controller);w.writeUnsigned(6);w.writeByteString(recovery);if(assertion!=null){w.writeUnsigned(7);w.writeEncoded(assertion);}w.writeUnsigned(8);w.writeEncoded(authority(authGeneration,null));w.writeUnsigned(9);w.writeEncoded(authority(delegationGeneration,null));return w.toByteArray();}
 private static byte[] encodeStatusState(State p,long sequence,int status){int n=7+(p.recovery==null?0:1)+(p.assertion==null?0:1);var w=new DeterministicCborWriter();w.writeMapHeader(n);w.writeUnsigned(1);w.writeUnsigned(3);w.writeUnsigned(2);w.writeByteString(p.identity);w.writeUnsigned(3);w.writeUnsigned(sequence);w.writeUnsigned(4);w.writeUnsigned(status);w.writeUnsigned(5);w.writeEncoded(p.controllerPolicy);if(p.recovery!=null){w.writeUnsigned(6);w.writeByteString(p.recovery);}if(p.assertion!=null){w.writeUnsigned(7);w.writeEncoded(p.assertion);}w.writeUnsigned(8);w.writeEncoded(authority(p.authentication.generation,p.authentication.policy));w.writeUnsigned(9);w.writeEncoded(authority(p.delegation.generation,p.delegation.policy));return w.toByteArray();}
 private static byte[] parseSinglePolicyPayload(byte[] bytes,String message){StrictCborReader r=new StrictCborReader(bytes);require(r.readMapHeader()==1&&r.readUnsigned()==1,message);byte[] p=r.readEncoded();require(r.done(),message);return p;}
 private static byte[] encodeControllerRotationState(State p,long sequence,byte[] controller){int n=7+(p.recovery==null?0:1)+(p.assertion==null?0:1);var w=new DeterministicCborWriter();w.writeMapHeader(n);w.writeUnsigned(1);w.writeUnsigned(3);w.writeUnsigned(2);w.writeByteString(p.identity);w.writeUnsigned(3);w.writeUnsigned(sequence);w.writeUnsigned(4);w.writeUnsigned(p.status);w.writeUnsigned(5);w.writeEncoded(controller);if(p.recovery!=null){w.writeUnsigned(6);w.writeByteString(p.recovery);}if(p.assertion!=null){w.writeUnsigned(7);w.writeEncoded(p.assertion);}w.writeUnsigned(8);w.writeEncoded(authority(p.version<3?0:p.authentication.generation,p.version<3?null:p.authentication.policy));w.writeUnsigned(9);w.writeEncoded(authority(p.version<3?0:p.delegation.generation,p.version<3?null:p.delegation.policy));return w.toByteArray();}
 private static byte[] encodePreservingDelegationState(State p,long sequence,Authority delegation){int n=7+(p.recovery==null?0:1)+(p.assertion==null?0:1);var w=new DeterministicCborWriter();w.writeMapHeader(n);w.writeUnsigned(1);w.writeUnsigned(3);w.writeUnsigned(2);w.writeByteString(p.identity);w.writeUnsigned(3);w.writeUnsigned(sequence);w.writeUnsigned(4);w.writeUnsigned(p.status);w.writeUnsigned(5);w.writeEncoded(p.controllerPolicy);if(p.recovery!=null){w.writeUnsigned(6);w.writeByteString(p.recovery);}if(p.assertion!=null){w.writeUnsigned(7);w.writeEncoded(p.assertion);}w.writeUnsigned(8);w.writeEncoded(authority(p.authentication.generation,p.authentication.policy));w.writeUnsigned(9);w.writeEncoded(authority(delegation.generation,delegation.policy));return w.toByteArray();}
 private static byte[] encodePreservingState(State p,long sequence,Authority authentication){int n=7+(p.recovery==null?0:1)+(p.assertion==null?0:1);var w=new DeterministicCborWriter();w.writeMapHeader(n);w.writeUnsigned(1);w.writeUnsigned(3);w.writeUnsigned(2);w.writeByteString(p.identity);w.writeUnsigned(3);w.writeUnsigned(sequence);w.writeUnsigned(4);w.writeUnsigned(p.status);w.writeUnsigned(5);w.writeEncoded(p.controllerPolicy);if(p.recovery!=null){w.writeUnsigned(6);w.writeByteString(p.recovery);}if(p.assertion!=null){w.writeUnsigned(7);w.writeEncoded(p.assertion);}w.writeUnsigned(8);w.writeEncoded(authority(authentication.generation,authentication.policy));w.writeUnsigned(9);w.writeEncoded(authority(p.delegation.generation,p.delegation.policy));return w.toByteArray();}
 private static CreatePayload parseCreatePayload(byte[] bytes){StrictCborReader r=new StrictCborReader(bytes);long n=r.readMapHeader(),prev=0;byte[] controller=null,recovery=null,assertion=null,authentication=null,delegation=null;for(long i=0;i<n;i++){long k=r.readUnsigned();require(k>prev,"CREATE payload labels");prev=k;if(k==1)controller=r.readEncoded();else if(k==2){recovery=r.readByteString();require(recovery.length==34,"CREATE recovery commitment length");}else if(k==3)assertion=r.readEncoded();else if(k==4)authentication=r.readEncoded();else if(k==5)delegation=r.readEncoded();else throw new IllegalArgumentException("unsupported CREATE payload field");}require(controller!=null,"CREATE controller policy");return new CreatePayload(controller,recovery,assertion,authentication,delegation);}
 private static byte[] encodeCreateState(byte[] identity,CreatePayload p){int n=7+(p.recoveryCommitment==null?0:1)+(p.assertionPolicy==null?0:1);var w=new DeterministicCborWriter();w.writeMapHeader(n);w.writeUnsigned(1);w.writeUnsigned(3);w.writeUnsigned(2);w.writeByteString(identity);w.writeUnsigned(3);w.writeUnsigned(1);w.writeUnsigned(4);w.writeUnsigned(1);w.writeUnsigned(5);w.writeEncoded(p.controllerPolicy);if(p.recoveryCommitment!=null){w.writeUnsigned(6);w.writeByteString(p.recoveryCommitment);}if(p.assertionPolicy!=null){w.writeUnsigned(7);w.writeEncoded(p.assertionPolicy);}w.writeUnsigned(8);w.writeEncoded(authority(0,p.authenticationPolicy));w.writeUnsigned(9);w.writeEncoded(authority(0,p.delegationPolicy));return w.toByteArray();}
 private static Payload parsePayload(byte[] bytes){StrictCborReader r=new StrictCborReader(bytes);long n=r.readMapHeader();require(n==1||n==2,"authentication payload");require(r.readUnsigned()==1,"authentication policy payload");byte[] p=null;if(r.peekByte()==0xf6)r.readNull();else p=r.readEncoded();Long disposition=null;if(n==2){require(r.readUnsigned()==2,"authentication disposition");disposition=r.readUnsigned();}require(r.done(),"authentication payload trailing");return new Payload(p,disposition);}
 private static void requireEmptyPayload(byte[] bytes){StrictCborReader r=new StrictCborReader(bytes);require(r.readMapHeader()==0&&r.done(),"reset payload must be empty");}
 private static Policy parsePolicy(byte[] bytes){
  StrictCborReader r=new StrictCborReader(bytes);require(r.readMapHeader()==2&&r.readUnsigned()==1,"policy");long threshold=r.readUnsigned();require(r.readUnsigned()==2,"policy methods");long n=r.readArrayHeader();List<Method> ms=new ArrayList<>();
  for(long i=0;i<n;i++){require(r.readMapHeader()==2&&r.readUnsigned()==1,"method");byte[] id=r.readByteString();require(r.readUnsigned()==2,"method cose");StrictCborReader c=new StrictCborReader(r.readEncoded());long fields=c.readMapHeader();byte[] pk=null;for(long j=0;j<fields;j++){long k=c.peekByte()>>>5==1?c.readNegative():c.readUnsigned();if(k==-2)pk=c.readByteString();else c.skipValue();}require(pk!=null&&pk.length==32,"Ed25519 public key");ms.add(new Method(id,pk));}
  require(r.done()&&threshold>0&&threshold<=ms.size(),"policy threshold");return new Policy(threshold,List.copyOf(ms));
 }
 private static boolean verifyThreshold(Policy p,List<Proof> proofs,byte[] signing){Set<String> used=new HashSet<>();long good=0;for(Proof proof:proofs)for(Method m:p.methods)if(Arrays.equals(proof.methodId,m.id)&&used.add(HexFormat.of().formatHex(m.id))&&verify(m.publicKey,signing,proof.signature))good++;return good>=p.threshold;}
 private static boolean verifyRecoveryThreshold(Policy p,List<Proof> proofs,byte[] op){
  Set<String> used=new HashSet<>();long good=0;
  for(Proof proof:proofs)for(Method m:p.methods)if(Arrays.equals(proof.methodId,m.id)&&used.add(HexFormat.of().formatHex(m.id))&&verify(m.publicKey,signing("OpenIdentity Recovery",op,m.id),proof.signature))good++;
  return good>=p.threshold;
 }
 private static boolean verifyPop(Policy p,List<Proof> proofs,byte[] op,String domain){if(proofs.size()!=p.methods.size())return false;for(Method m:p.methods){Proof found=null;for(Proof x:proofs)if(Arrays.equals(x.methodId,m.id)){if(found!=null)return false;found=x;}if(found==null||!verify(m.publicKey,signing(domain,op,m.id),found.signature))return false;}return true;}
 private static boolean verify(byte[] pk,byte[] msg,byte[] sig){if(sig.length!=64)return false;var v=new Ed25519Signer();v.init(false,new Ed25519PublicKeyParameters(pk,0));v.update(msg,0,msg.length);return v.verifySignature(sig);}
 private static byte[] signing(String domain,byte[] op,byte[] method){var w=new DeterministicCborWriter();w.writeArrayHeader(method==null?3:4);w.writeTextString(domain);w.writeUnsigned(1);w.writeByteString(op);if(method!=null)w.writeByteString(method);return w.toByteArray();}
 private static byte[] authority(long generation,byte[] policy){var w=new DeterministicCborWriter();w.writeMapHeader(policy==null?1:2);w.writeUnsigned(1);w.writeUnsigned(generation);if(policy!=null){w.writeUnsigned(2);w.writeEncoded(policy);}return w.toByteArray();}
 private static byte[] encodeStateV3(State p,long sequence,byte[] authentication){int n=7+(p.recovery==null?0:1)+(p.assertion==null?0:1);var w=new DeterministicCborWriter();w.writeMapHeader(n);w.writeUnsigned(1);w.writeUnsigned(3);w.writeUnsigned(2);w.writeByteString(p.identity);w.writeUnsigned(3);w.writeUnsigned(sequence);w.writeUnsigned(4);w.writeUnsigned(p.status);w.writeUnsigned(5);w.writeEncoded(p.controllerPolicy);if(p.recovery!=null){w.writeUnsigned(6);w.writeByteString(p.recovery);}if(p.assertion!=null){w.writeUnsigned(7);w.writeEncoded(p.assertion);}w.writeUnsigned(8);w.writeEncoded(authority(0,authentication));w.writeUnsigned(9);w.writeEncoded(authority(0,null));return w.toByteArray();}
 private static void require(boolean ok,String message){if(!ok)throw new IllegalArgumentException(message);}
}
