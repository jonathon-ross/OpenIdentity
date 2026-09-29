package org.openidentity.vectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Independent Java verification for draft Protocol v2 / IdentityState v3.
 *
 * This class deliberately does not modify or call the frozen v0.1 vector
 * generator. It reconstructs v3 canonical bytes using the low-level
 * deterministic CBOR and crypto primitives and compares them with the
 * Python-generated draft bundle.
 */
public final class ProtocolV2V3Vectors {
    private static final byte[] IDENTITY = range(0, 32);

    private ProtocolV2V3Vectors() {}

    public static void main(String[] args) throws Exception {
        Path root = Path.of("..", "..").toAbsolutePath().normalize();
        JsonNode doc = new ObjectMapper().readTree(
                root.resolve("test-vectors/generated/protocol-v2-identity-state-v3.json").toFile());
        require("suite specification",
                "OpenIdentity Protocol v2 / IdentityState v3".equals(doc.path("specification").asText()));
        require("positive vector count", doc.path("vectors").size() == 20);
        require("invalid vector count", doc.path("invalidVectors").size() == 32);

        verifyV301(find(doc, "V301"));
        verifyV302(find(doc, "V302"));
        verifyV303(find(doc, "V303"));
        verifyV304(find(doc, "V304"));

        System.out.println();
        System.out.println("================================================");
        System.out.println("PROTOCOL V2 / IDENTITYSTATE V3 JAVA V301-V304 VERIFIED");
        System.out.println("================================================");
    }

    private static void verifyV301(JsonNode v) throws Exception {
        Key c = key("OpenIdentity protocol-v2 v3 V301 controller Ed25519 seed", 0);
        byte[] cp = policy(c.method);
        byte[] op = operation(1, 1, null, map(entry(1, cp)));
        byte[] signing = signing("OpenIdentity Operation", op, null);
        byte[] sig = c.ed.sign(signing);
        require("V301 OperationBytes", eq(v, "operationBytesHex", op));
        require("V301 signing input", eq(v, "operationSigningBytesHex", signing));
        require("V301 signature", eq(v, "controllerSignatureHex", sig));
        byte[] state = state(3, 1, 1, cp, null, null,
                authority(0, null), authority(0, null));
        require("V301 StateBytes", eq(v, "stateBytesHex", state));
        require("V301 StateHash", eq(v, "stateHashHex", StateHash.sha256Multihash(state)));
    }

    private static void verifyV302(JsonNode v) throws Exception {
        Key c = key("OpenIdentity protocol-v2 v3 V302 controller Ed25519 seed", 0);
        Key a = key("OpenIdentity protocol-v2 v3 V302 authentication Ed25519 seed", 16);
        byte[] cp=policy(c.method), ap=policy(a.method);
        byte[] op=operation(1,1,null,map(entry(1,cp),entry(4,ap)));
        byte[] cs=signing("OpenIdentity Operation",op,null);
        byte[] as=signing("OpenIdentity Authentication Proof",op,a.id);
        require("V302 OperationBytes",eq(v,"operationBytesHex",op));
        require("V302 controller signature",eq(v,"controllerSignatureHex",c.ed.sign(cs)));
        require("V302 authentication signature",eq(v,"authenticationProofSignatureHex",a.ed.sign(as)));
        byte[] state=state(3,1,1,cp,null,null,authority(0,ap),authority(0,null));
        require("V302 StateBytes",eq(v,"stateBytesHex",state));
        require("V302 StateHash",eq(v,"stateHashHex",StateHash.sha256Multihash(state)));
    }

    private static void verifyV303(JsonNode v) throws Exception {
        Key c=key("OpenIdentity protocol-v2 v3 V303 controller Ed25519 seed",0);
        Key a=key("OpenIdentity protocol-v2 v3 V303 authentication Ed25519 seed",16);
        Key s=key("OpenIdentity protocol-v2 v3 V303 assertion Ed25519 seed",32);
        Key d=key("OpenIdentity protocol-v2 v3 V303 delegation Ed25519 seed",48);
        byte[] cp=policy(c.method),ap=policy(a.method),sp=policy(s.method),dp=policy(d.method);
        byte[] op=operation(1,1,null,map(entry(1,cp),entry(3,sp),entry(4,ap),entry(5,dp)));
        require("V303 OperationBytes",eq(v,"operationBytesHex",op));
        require("V303 controller signature",eq(v,"controllerSignatureHex",c.ed.sign(signing("OpenIdentity Operation",op,null))));
        require("V303 authentication signature",eq(v,"authenticationProofSignatureHex",a.ed.sign(signing("OpenIdentity Authentication Proof",op,a.id))));
        require("V303 assertion signature",eq(v,"assertionProofSignatureHex",s.ed.sign(signing("OpenIdentity Assertion Proof",op,s.id))));
        require("V303 delegation signature",eq(v,"delegationProofSignatureHex",d.ed.sign(signing("OpenIdentity Delegation Proof",op,d.id))));
        byte[] state=state(3,1,1,cp,null,sp,authority(0,ap),authority(0,dp));
        require("V303 StateBytes",eq(v,"stateBytesHex",state));
        require("V303 StateHash",eq(v,"stateHashHex",StateHash.sha256Multihash(state)));
    }

    private static void verifyV304(JsonNode v) throws Exception {
        Key c=key("OpenIdentity protocol-v2 v3 V304 controller Ed25519 seed",0);
        Key a=key("OpenIdentity protocol-v2 v3 V304 authentication Ed25519 seed",16);
        byte[] cp=policy(c.method),ap=policy(a.method);
        byte[] previous=state(2,1,1,cp,null,null,null,null);
        byte[] ph=StateHash.sha256Multihash(previous);
        byte[] op=operation(6,2,ph,map(entry(1,ap)));
        require("V304 previous StateBytes",eq(v,"previousStateBytesHex",previous));
        require("V304 previous StateHash",eq(v,"previousStateHashHex",ph));
        require("V304 OperationBytes",eq(v,"operationBytesHex",op));
        require("V304 controller signature",eq(v,"controllerSignatureHex",c.ed.sign(signing("OpenIdentity Operation",op,null))));
        require("V304 authentication signature",eq(v,"authenticationProofSignatureHex",a.ed.sign(signing("OpenIdentity Authentication Proof",op,a.id))));
        byte[] result=state(3,2,1,cp,null,null,authority(0,ap),authority(0,null));
        require("V304 StateBytes",eq(v,"stateBytesHex",result));
        require("V304 StateHash",eq(v,"stateHashHex",StateHash.sha256Multihash(result)));
    }

    private record Key(Ed25519Support ed, byte[] id, byte[] method) {}
    private record Entry(long label, byte[] encoded) {}

    private static Key key(String label,int start) throws Exception {
        byte[] seed=MessageDigest.getInstance("SHA-256").digest(label.getBytes(StandardCharsets.US_ASCII));
        Ed25519Support ed=new Ed25519Support(seed);
        byte[] id=range(start,16);
        byte[] method=OpenIdentityCbor.verificationMethod(id,OpenIdentityCbor.ed25519CoseKey(ed.publicKey())).encoded();
        return new Key(ed,id,method);
    }

    private static byte[] policy(byte[] method) {
        var c=new DeterministicCborWriter();
        c.writeMapHeader(2); c.writeUnsigned(1); c.writeUnsigned(1);
        c.writeUnsigned(2); c.writeArrayHeader(1); c.writeEncoded(method);
        return c.toByteArray();
    }

    private static byte[] authority(long generation,byte[] policy) {
        var c=new DeterministicCborWriter();
        c.writeMapHeader(policy==null?1:2); c.writeUnsigned(1); c.writeUnsigned(generation);
        if(policy!=null){c.writeUnsigned(2);c.writeEncoded(policy);}
        return c.toByteArray();
    }

    private static byte[] operation(long type,long seq,byte[] prev,byte[] payload) {
        var c=new DeterministicCborWriter(); c.writeMapHeader(6);
        c.writeUnsigned(1);c.writeUnsigned(2); c.writeUnsigned(2);c.writeUnsigned(type);
        c.writeUnsigned(3);c.writeByteString(IDENTITY); c.writeUnsigned(4);c.writeUnsigned(seq);
        c.writeUnsigned(5); if(prev==null)c.writeNull(); else c.writeByteString(prev);
        c.writeUnsigned(6);c.writeEncoded(payload); return c.toByteArray();
    }

    private static byte[] state(int version,long seq,int status,byte[] cp,byte[] recovery,byte[] assertion,
                                byte[] auth,byte[] delegation) {
        int n=5+(recovery==null?0:1)+(assertion==null?0:1)+(auth==null?0:1)+(delegation==null?0:1);
        var c=new DeterministicCborWriter();c.writeMapHeader(n);
        c.writeUnsigned(1);c.writeUnsigned(version);c.writeUnsigned(2);c.writeByteString(IDENTITY);
        c.writeUnsigned(3);c.writeUnsigned(seq);c.writeUnsigned(4);c.writeUnsigned(status);
        c.writeUnsigned(5);c.writeEncoded(cp);
        if(recovery!=null){c.writeUnsigned(6);c.writeByteString(recovery);}
        if(assertion!=null){c.writeUnsigned(7);c.writeEncoded(assertion);}
        if(auth!=null){c.writeUnsigned(8);c.writeEncoded(auth);}
        if(delegation!=null){c.writeUnsigned(9);c.writeEncoded(delegation);}
        return c.toByteArray();
    }

    private static byte[] signing(String domain,byte[] op,byte[] methodId) {
        var c=new DeterministicCborWriter();c.writeArrayHeader(methodId==null?3:4);
        c.writeTextString(domain);c.writeUnsigned(1);c.writeByteString(op);
        if(methodId!=null)c.writeByteString(methodId);return c.toByteArray();
    }

    private static Entry entry(long label,byte[] value){return new Entry(label,value);}
    private static byte[] map(Entry... entries){
        var c=new DeterministicCborWriter();c.writeMapHeader(entries.length);
        for(Entry e:entries){c.writeUnsigned(e.label);c.writeEncoded(e.encoded);}return c.toByteArray();
    }
    private static byte[] range(int start,int count){byte[] b=new byte[count];for(int i=0;i<count;i++)b[i]=(byte)(start+i);return b;}
    private static JsonNode find(JsonNode doc,String id){
        for(JsonNode v:doc.path("vectors"))if(id.equals(v.path("id").asText()))return v;
        throw new IllegalStateException("Missing "+id);
    }
    private static boolean eq(JsonNode v,String field,byte[] actual){return Arrays.equals(Hex.decode(v.path(field).asText()),actual);}
    private static void require(String name,boolean ok){if(!ok)throw new IllegalStateException(name+" failed");System.out.println("  "+name+": PASS");}
}
