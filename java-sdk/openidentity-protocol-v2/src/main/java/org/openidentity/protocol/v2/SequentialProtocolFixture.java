package org.openidentity.protocol.v2;

import com.fasterxml.jackson.databind.*;import com.fasterxml.jackson.databind.node.*;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.openidentity.cbor.*;import org.openidentity.core.*;
import java.nio.charset.StandardCharsets;import java.security.MessageDigest;import java.util.*;

public final class SequentialProtocolFixture {
 static final HexFormat H=HexFormat.of();static final ObjectMapper J=new ObjectMapper();static final byte[] ID=range(0,32);
 record Key(byte[] id,Ed25519PrivateKeyParameters key,byte[] method){}
 public static void main(String[] args)throws Exception{
  Key c=key("OpenIdentity Sui sequential controller",0),a=key("OpenIdentity Sui sequential authentication",16),d=key("OpenIdentity Sui sequential delegation",32);
  byte[] cp=policy(c.method),ap=policy(a.method),dp=policy(d.method);
  ArrayNode steps=J.createArrayNode();

  byte[] createOp=operation(1,1,null,map(entry(1,cp)));byte[] createSigned=signed(createOp,proofs(2,proof(c,signing("OpenIdentity Operation",createOp,null))));
  VerifiedIdentityCreation created=ProtocolV2TransitionVerifier.verifyCreate(createSigned);steps.add(step("CREATE",createSigned,null,created.stateBytes(),created.stateHash(),1));

  byte[] authOp=operation(6,2,created.stateHash(),map(entry(1,ap)));byte[] authSigned=signed(authOp,proofs(2,proof(c,signing("OpenIdentity Operation",authOp,null))),proofs(5,proof(a,signing("OpenIdentity Authentication Proof",authOp,a.id))));
  var t2=ProtocolV2TransitionVerifier.verifyAndApply(created.stateBytes(),authSigned);steps.add(step("SET_AUTHENTICATION_POLICY",authSigned,created.stateBytes(),t2.successorStateBytes(),t2.successorStateHash(),2));

  byte[] delOp=operation(7,3,t2.successorStateHash(),map(entry(1,dp)));byte[] delSigned=signed(delOp,proofs(2,proof(c,signing("OpenIdentity Operation",delOp,null))),proofs(7,proof(d,signing("OpenIdentity Delegation Proof",delOp,d.id))));
  var t3=ProtocolV2TransitionVerifier.verifyAndApply(t2.successorStateBytes(),delSigned);steps.add(step("SET_DELEGATION_POLICY",delSigned,t2.successorStateBytes(),t3.successorStateBytes(),t3.successorStateHash(),3));

  byte[] resetOp=operation(9,4,t3.successorStateHash(),map());byte[] resetSigned=signed(resetOp,proofs(2,proof(c,signing("OpenIdentity Operation",resetOp,null))));
  var t4=ProtocolV2TransitionVerifier.verifyAndApply(t3.successorStateBytes(),resetSigned);steps.add(step("RESET_DELEGATIONS",resetSigned,t3.successorStateBytes(),t4.successorStateBytes(),t4.successorStateHash(),4));

  ObjectNode out=J.createObjectNode();out.put("suite","OpenIdentity Protocol v2 sequential Sui integration fixture");out.put("openidentityIdHex",H.formatHex(ID));out.set("steps",steps);System.out.println(J.writerWithDefaultPrettyPrinter().writeValueAsString(out));
 }
 static ObjectNode step(String name,byte[] signed,byte[] prev,byte[] state,byte[] hash,long seq){ObjectNode o=J.createObjectNode();o.put("name",name);o.put("sequence",seq);if(prev!=null)o.put("previousStateBytesHex",H.formatHex(prev));o.put("signedOperationBytesHex",H.formatHex(signed));o.put("stateBytesHex",H.formatHex(state));o.put("stateHashHex",H.formatHex(hash));return o;}
 record Entry(long label,byte[] value){}record ProofField(long label,byte[] proof){}
 static byte[] operation(long type,long seq,byte[] prev,byte[] payload){var w=new DeterministicCborWriter();w.writeMapHeader(6);w.writeUnsigned(1);w.writeUnsigned(2);w.writeUnsigned(2);w.writeUnsigned(type);w.writeUnsigned(3);w.writeByteString(ID);w.writeUnsigned(4);w.writeUnsigned(seq);w.writeUnsigned(5);if(prev==null)w.writeNull();else w.writeByteString(prev);w.writeUnsigned(6);w.writeEncoded(payload);return w.toByteArray();}
 static byte[] map(Entry... es){var w=new DeterministicCborWriter();w.writeMapHeader(es.length);for(Entry e:es){w.writeUnsigned(e.label);w.writeEncoded(e.value);}return w.toByteArray();}
 static Entry entry(long l,byte[] v){return new Entry(l,v);}
 static byte[] signed(byte[] op,ProofField... fs){var w=new DeterministicCborWriter();w.writeMapHeader(1+fs.length);w.writeUnsigned(1);w.writeEncoded(op);for(ProofField f:fs){w.writeUnsigned(f.label);w.writeArrayHeader(1);w.writeEncoded(f.proof);}return w.toByteArray();}
 static ProofField proofs(long l,byte[] p){return new ProofField(l,p);}
 static byte[] proof(Key k,byte[] msg){var w=new DeterministicCborWriter();w.writeMapHeader(2);w.writeUnsigned(1);w.writeByteString(k.id);w.writeUnsigned(2);w.writeByteString(sign(k,msg));return w.toByteArray();}
 static byte[] signing(String domain,byte[] op,byte[] id){var w=new DeterministicCborWriter();w.writeArrayHeader(id==null?3:4);w.writeTextString(domain);w.writeUnsigned(1);w.writeByteString(op);if(id!=null)w.writeByteString(id);return w.toByteArray();}
 static byte[] sign(Key k,byte[] msg){var s=new Ed25519Signer();s.init(true,k.key);s.update(msg,0,msg.length);return s.generateSignature();}
 static Key key(String label,int start)throws Exception{byte[] seed=MessageDigest.getInstance("SHA-256").digest(label.getBytes(StandardCharsets.US_ASCII));var k=new Ed25519PrivateKeyParameters(seed,0);byte[] id=range(start,16);return new Key(id,k,method(id,k.generatePublicKey().getEncoded()));}
 static byte[] method(byte[] id,byte[] pk){var cose=new DeterministicCborWriter();cose.writeMapHeader(4);cose.writeUnsigned(1);cose.writeUnsigned(1);cose.writeUnsigned(3);cose.writeNegative(-8);cose.writeNegative(-1);cose.writeUnsigned(6);cose.writeNegative(-2);cose.writeByteString(pk);var m=new DeterministicCborWriter();m.writeMapHeader(2);m.writeUnsigned(1);m.writeByteString(id);m.writeUnsigned(2);m.writeEncoded(cose.toByteArray());return m.toByteArray();}
 static byte[] policy(byte[] method){var w=new DeterministicCborWriter();w.writeMapHeader(2);w.writeUnsigned(1);w.writeUnsigned(1);w.writeUnsigned(2);w.writeArrayHeader(1);w.writeEncoded(method);return w.toByteArray();}
 static byte[] range(int start,int n){byte[] b=new byte[n];for(int i=0;i<n;i++)b[i]=(byte)(start+i);return b;}
}
