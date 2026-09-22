package org.openidentity.vectors;

import com.fasterxml.jackson.databind.*;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;

public final class GenerateVectors {
    private GenerateVectors(){}
    private record HybridCreateResult(byte[] controllerPolicy,byte[] operation,byte[] signingInput,byte[] signedOperation,byte[] identityState,byte[] stateHash){}

    public static void main(String[] args){
        System.out.println();
        System.out.println("OpenIdentity Cryptographic Test Vector Generator");
        System.out.println("================================================");
        System.out.println();
        generateV01(); HybridCreateResult v02=generateV02(); generateV03(v02); generateV04(v02); generateAllInvalidVectors(v02);
        generateNormativeVectorFile();
        System.out.println("================================================");
        System.out.println("ALL JAVA TEST VECTORS GENERATED SUCCESSFULLY");
        System.out.println("================================================");
    }

    private static void generateV01(){
        var ed=new Ed25519Support(TestKeys.ED25519_SEED);byte[] pk=ed.publicKey(),ck=OpenIdentityCbor.ed25519CoseKey(pk);
        var vm=OpenIdentityCbor.verificationMethod(TestKeys.ED25519_METHOD_ID,ck);byte[] pol=OpenIdentityCbor.singlePolicy(vm);
        byte[] op=OpenIdentityCbor.createOperation(TestKeys.IDENTITY,pol),si=OpenIdentityCbor.operationSigningInput(op),sig=ed.sign(si);
        if(!ed.verify(si,sig))throw new IllegalStateException("V01 Ed25519 verification failed");
        var proof=OpenIdentityCbor.authorizationProof(TestKeys.ED25519_METHOD_ID,sig);byte[] so=OpenIdentityCbor.signedOperation(op,List.of(proof));






        Map<String,Object> v01 = new LinkedHashMap<>();
        v01.put("id","V01");
        v01.put("description","SINGLE Ed25519 CREATE");
        put(v01,"identityHex",TestKeys.IDENTITY);
        put(v01,"ed25519MethodIdHex",TestKeys.ED25519_METHOD_ID);
        put(v01,"ed25519PublicKeyHex",pk);
        put(v01,"ed25519CoseKeyHex",ck);
        put(v01,"ed25519VerificationMethodHex",vm.encoded());
        put(v01,"controllerPolicyHex",pol);
        put(v01,"operationBytesHex",op);
        put(v01,"signingInputHex",si);
        put(v01,"ed25519SignatureHex",sig);
        put(v01,"ed25519AuthorizationProofHex",proof.encoded());
        put(v01,"signedOperationHex",so);
        v01.put("ed25519PublicKeyLength",pk.length);
        v01.put("ed25519SignatureLength",sig.length);

        writeJson(
                "crypto-v01-java.json",
                doc(v01));

        success("crypto-v01-java.json");

        success("V01 complete"); blankLine();
    }

    private static HybridCreateResult generateV02(){
        section("V02", "Hybrid Ed25519 + ML-DSA-65 CREATE");
        var ed=new Ed25519Support(TestKeys.ED25519_SEED);var ml=new MlDsa65Support(TestKeys.ML_DSA_SEED);
        byte[] ep=ed.publicKey(),mp=ml.publicKey(),ec=OpenIdentityCbor.ed25519CoseKey(ep),mc=OpenIdentityCbor.mlDsa65CoseKey(mp);
        var em=OpenIdentityCbor.verificationMethod(TestKeys.ED25519_METHOD_ID,ec);var mm=OpenIdentityCbor.verificationMethod(TestKeys.ML_DSA_METHOD_ID,mc);
        byte[] pol=OpenIdentityCbor.thresholdPolicy(2,List.of(em,mm)),op=OpenIdentityCbor.createOperation(TestKeys.IDENTITY,pol),si=OpenIdentityCbor.operationSigningInput(op);
        byte[] es=ed.sign(si),ms=ml.sign(si);if(!ed.verify(si,es)||!ml.verify(si,ms))throw new IllegalStateException("V02 signature verification failed");
        var epr=OpenIdentityCbor.authorizationProof(TestKeys.ED25519_METHOD_ID,es);var mpr=OpenIdentityCbor.authorizationProof(TestKeys.ML_DSA_METHOD_ID,ms);
        byte[] so=OpenIdentityCbor.signedOperation(op,List.of(epr,mpr));
        byte[] state=OpenIdentityCbor.activeIdentityState(TestKeys.IDENTITY,1,pol),hash=StateHash.sha256Multihash(state);

        Map<String,Object> v=new LinkedHashMap<>();v.put("id","V02");v.put("description","Hybrid Ed25519 + ML-DSA-65 CREATE");
        put(v,"identityHex",TestKeys.IDENTITY);put(v,"ed25519MethodIdHex",TestKeys.ED25519_METHOD_ID);put(v,"mlDsa65MethodIdHex",TestKeys.ML_DSA_METHOD_ID);
        put(v,"ed25519PublicKeyHex",ep);put(v,"mlDsa65PublicKeyHex",mp);put(v,"ed25519CoseKeyHex",ec);put(v,"mlDsa65CoseKeyHex",mc);
        put(v,"ed25519VerificationMethodHex",em.encoded());put(v,"mlDsa65VerificationMethodHex",mm.encoded());put(v,"controllerPolicyHex",pol);
        put(v,"operationBytesHex",op);put(v,"signingInputHex",si);put(v,"ed25519SignatureHex",es);put(v,"mlDsa65SignatureHex",ms);
        put(v,"ed25519AuthorizationProofHex",epr.encoded());put(v,"mlDsa65AuthorizationProofHex",mpr.encoded());put(v,"signedOperationHex",so);
        put(v,"identityStateHex",state);put(v,"stateHashHex",hash);
        v.put("ed25519PublicKeyLength",ep.length);v.put("mlDsa65PublicKeyLength",mp.length);v.put("ed25519SignatureLength",es.length);v.put("mlDsa65SignatureLength",ms.length);
        writeJson("crypto-v02-java.json",doc(v));

        success("Ed25519 signature verified"); success("ML-DSA-65 signature verified"); success("IdentityState and StateHash generated"); success("crypto-v02-java.json"); blankLine();
        return new HybridCreateResult(pol,op,si,so,state,hash);
    }

    private static void generateV03(HybridCreateResult v02){
        section("V03", "Canonical Ordering");
        var ed=new Ed25519Support(TestKeys.ED25519_SEED);var ml=new MlDsa65Support(TestKeys.ML_DSA_SEED);
        var em=OpenIdentityCbor.verificationMethod(TestKeys.ED25519_METHOD_ID,OpenIdentityCbor.ed25519CoseKey(ed.publicKey()));
        var mm=OpenIdentityCbor.verificationMethod(TestKeys.ML_DSA_METHOD_ID,OpenIdentityCbor.mlDsa65CoseKey(ml.publicKey()));
        byte[] pol=OpenIdentityCbor.thresholdPolicy(2,List.of(mm,em)),op=OpenIdentityCbor.createOperation(TestKeys.IDENTITY,pol),si=OpenIdentityCbor.operationSigningInput(op);
        var ep=OpenIdentityCbor.authorizationProof(TestKeys.ED25519_METHOD_ID,ed.sign(si));var mp=OpenIdentityCbor.authorizationProof(TestKeys.ML_DSA_METHOD_ID,ml.sign(si));
        byte[] so=OpenIdentityCbor.signedOperation(op,List.of(mp,ep));
        same("ControllerPolicy",v02.controllerPolicy(),pol);same("OperationBytes",v02.operation(),op);same("SigningInput",v02.signingInput(),si);same("SignedOperation",v02.signedOperation(),so);
        Map<String,Object> v=new LinkedHashMap<>();v.put("id","V03");v.put("description","Canonical ordering with reversed method and proof input");
        v.put("inputMethodOrder",List.of("ML-DSA-65","Ed25519"));v.put("inputProofOrder",List.of("ML-DSA-65","Ed25519"));
        put(v,"controllerPolicyHex",pol);put(v,"operationBytesHex",op);put(v,"signingInputHex",si);put(v,"signedOperationHex",so);
        v.put("matchesV02ControllerPolicy",true);v.put("matchesV02OperationBytes",true);v.put("matchesV02SigningInput",true);v.put("matchesV02SignedOperation",true);
        writeJson("crypto-v03-java.json",doc(v));success("Canonical outputs match V02"); success("crypto-v03-java.json"); blankLine();
    }


    private static void generateV04(HybridCreateResult v02){
        section("V04", "ROTATE_CONTROLLER + Proof of Possession");

        var oldEd=new Ed25519Support(TestKeys.ED25519_SEED);
        var oldMl=new MlDsa65Support(TestKeys.ML_DSA_SEED);
        var newEd=new Ed25519Support(TestKeys.ED25519_SEED_B);
        var newMl=new MlDsa65Support(TestKeys.ML_DSA_SEED_B);

        byte[] newEdPk=newEd.publicKey(), newMlPk=newMl.publicKey();
        requireLength("new Ed25519 public key",newEdPk,32);
        requireLength("new ML-DSA-65 public key",newMlPk,1952);

        byte[] newEdCose=OpenIdentityCbor.ed25519CoseKey(newEdPk);
        byte[] newMlCose=OpenIdentityCbor.mlDsa65CoseKey(newMlPk);
        var newEdMethod=OpenIdentityCbor.verificationMethod(TestKeys.ED25519_METHOD_ID_B,newEdCose);
        var newMlMethod=OpenIdentityCbor.verificationMethod(TestKeys.ML_DSA_METHOD_ID_B,newMlCose);
        byte[] newPolicy=OpenIdentityCbor.thresholdPolicy(2,List.of(newEdMethod,newMlMethod));

        byte[] operation=OpenIdentityCbor.rotateControllerOperation(
                TestKeys.IDENTITY,2,v02.stateHash(),newPolicy);

        byte[] authInput=OpenIdentityCbor.operationSigningInput(operation);
        byte[] oldEdSig=oldEd.sign(authInput), oldMlSig=oldMl.sign(authInput);
        if(!oldEd.verify(authInput,oldEdSig)||!oldMl.verify(authInput,oldMlSig))
            throw new IllegalStateException("V04 old-controller authorization failed");

        var oldEdProof=OpenIdentityCbor.authorizationProof(TestKeys.ED25519_METHOD_ID,oldEdSig);
        var oldMlProof=OpenIdentityCbor.authorizationProof(TestKeys.ML_DSA_METHOD_ID,oldMlSig);

        byte[] newEdPopInput=OpenIdentityCbor.controllerProofSigningInput(operation,TestKeys.ED25519_METHOD_ID_B);
        byte[] newEdPopSig=newEd.sign(newEdPopInput);
        if(!newEd.verify(newEdPopInput,newEdPopSig))
            throw new IllegalStateException("V04 new Ed25519 PoP failed");
        var newEdPop=OpenIdentityCbor.controllerProof(TestKeys.ED25519_METHOD_ID_B,newEdPopSig);

        byte[] newMlPopInput=OpenIdentityCbor.controllerProofSigningInput(operation,TestKeys.ML_DSA_METHOD_ID_B);
        byte[] newMlPopSig=newMl.sign(newMlPopInput);
        if(!newMl.verify(newMlPopInput,newMlPopSig))
            throw new IllegalStateException("V04 new ML-DSA-65 PoP failed");
        var newMlPop=OpenIdentityCbor.controllerProof(TestKeys.ML_DSA_METHOD_ID_B,newMlPopSig);

        byte[] signed=OpenIdentityCbor.signedOperation(
                operation,List.of(oldEdProof,oldMlProof),List.of(newEdPop,newMlPop));

        byte[] resultState=OpenIdentityCbor.activeIdentityState(TestKeys.IDENTITY,2,newPolicy);
        byte[] resultHash=StateHash.sha256Multihash(resultState);
        if(Arrays.equals(v02.stateHash(),resultHash))
            throw new IllegalStateException("V04 resulting StateHash unexpectedly equals V02 StateHash");

        requireLength("old Ed25519 signature",oldEdSig,64);
        requireLength("old ML-DSA-65 signature",oldMlSig,3309);
        requireLength("new Ed25519 PoP signature",newEdPopSig,64);
        requireLength("new ML-DSA-65 PoP signature",newMlPopSig,3309);

        Map<String,Object> v=new LinkedHashMap<>();
        v.put("id","V04");
        v.put("description","Hybrid ROTATE_CONTROLLER with new-controller proof of possession");
        put(v,"identityHex",TestKeys.IDENTITY); v.put("sequence",2);
        put(v,"previousIdentityStateHex",v02.identityState());
        put(v,"previousStateHashHex",v02.stateHash());

        put(v,"oldEd25519MethodIdHex",TestKeys.ED25519_METHOD_ID);
        put(v,"oldMlDsa65MethodIdHex",TestKeys.ML_DSA_METHOD_ID);
        put(v,"oldEd25519PublicKeyHex",oldEd.publicKey());
        put(v,"oldMlDsa65PublicKeyHex",oldMl.publicKey());

        put(v,"newEd25519MethodIdHex",TestKeys.ED25519_METHOD_ID_B);
        put(v,"newMlDsa65MethodIdHex",TestKeys.ML_DSA_METHOD_ID_B);
        put(v,"newEd25519PublicKeyHex",newEdPk); put(v,"newMlDsa65PublicKeyHex",newMlPk);
        put(v,"newEd25519CoseKeyHex",newEdCose); put(v,"newMlDsa65CoseKeyHex",newMlCose);
        put(v,"newEd25519VerificationMethodHex",newEdMethod.encoded());
        put(v,"newMlDsa65VerificationMethodHex",newMlMethod.encoded());
        put(v,"newControllerPolicyHex",newPolicy);

        put(v,"operationBytesHex",operation);
        put(v,"authorizationSigningInputHex",authInput);
        put(v,"oldEd25519AuthorizationSignatureHex",oldEdSig);
        put(v,"oldMlDsa65AuthorizationSignatureHex",oldMlSig);
        put(v,"oldEd25519AuthorizationProofHex",oldEdProof.encoded());
        put(v,"oldMlDsa65AuthorizationProofHex",oldMlProof.encoded());

        put(v,"newEd25519PopSigningInputHex",newEdPopInput);
        put(v,"newEd25519PopSignatureHex",newEdPopSig);
        put(v,"newEd25519ControllerProofHex",newEdPop.encoded());
        put(v,"newMlDsa65PopSigningInputHex",newMlPopInput);
        put(v,"newMlDsa65PopSignatureHex",newMlPopSig);
        put(v,"newMlDsa65ControllerProofHex",newMlPop.encoded());

        put(v,"signedOperationHex",signed);
        put(v,"resultingIdentityStateHex",resultState);
        put(v,"resultingStateHashHex",resultHash);
        v.put("oldControllerThreshold",2); v.put("newControllerThreshold",2);
        v.put("authorizationProofCount",2); v.put("controllerProofCount",2);
        v.put("oldEd25519SignatureLength",oldEdSig.length);
        v.put("oldMlDsa65SignatureLength",oldMlSig.length);
        v.put("newEd25519PopSignatureLength",newEdPopSig.length);
        v.put("newMlDsa65PopSignatureLength",newMlPopSig.length);

        writeJson("crypto-v04-java.json",doc(v));




        System.out.println("Old controller authorization: PASS");
        System.out.println("New controller proof of possession: PASS");
        success("Old controller authorization verified"); success("New controller proof-of-possession verified"); success("Resulting IdentityState and StateHash generated"); success("crypto-v04-java.json"); blankLine();
    }

    private static void requireLength(String name,byte[] value,int expected){
        if(value==null||value.length!=expected)
            throw new IllegalStateException(name+" length expected "+expected+" but got "+(value==null?"null":value.length));
    }



    private static void generateAllInvalidVectors(HybridCreateResult v02){
        generateInvalidVectors(v02);
        generateInvalidVectorsI06ToI20(v02);
        try{
            Path root=Path.of("..","..").toAbsolutePath().normalize();
            Path dir=root.resolve("test-vectors").resolve("generated");
            ObjectMapper mapper=new ObjectMapper();
            Map<?,?> a=mapper.readValue(dir.resolve("crypto-invalid-java.json").toFile(),Map.class);
            Map<?,?> b=mapper.readValue(dir.resolve("crypto-invalid-i06-i20-java.json").toFile(),Map.class);
            List<Object> all=new java.util.ArrayList<>();
            all.addAll((List<?>)a.get("vectors")); all.addAll((List<?>)b.get("vectors"));
            Map<String,Object>d=new LinkedHashMap<>();
            d.put("specification","OpenIdentity Cryptographic Agility");d.put("version","0.1");
            d.put("type","invalid-conformance-vectors");d.put("vectors",all);
            writeJson("crypto-invalid-java.json",d);
            Files.deleteIfExists(dir.resolve("crypto-invalid-i06-i20-java.json"));
            success("20 invalid vectors consolidated"); success("crypto-invalid-java.json"); blankLine();
        }catch(IOException e){throw new IllegalStateException("Unable to consolidate invalid vectors",e);}
    }

    private static void generateInvalidVectors(HybridCreateResult v02){
        section("INVALID", "I01-I05");
        var ed=new Ed25519Support(TestKeys.ED25519_SEED);
        var ml=new MlDsa65Support(TestKeys.ML_DSA_SEED);
        byte[] ec=OpenIdentityCbor.ed25519CoseKey(ed.publicKey());
        byte[] mc=OpenIdentityCbor.mlDsa65CoseKey(ml.publicKey());
        var em=OpenIdentityCbor.verificationMethod(TestKeys.ED25519_METHOD_ID,ec);
        var mm=OpenIdentityCbor.verificationMethod(TestKeys.ML_DSA_METHOD_ID,mc);
        List<Map<String,Object>> vs=new java.util.ArrayList<>();

        byte[] i01=rawCreateOperation(TestKeys.IDENTITY,2,null,v02.controllerPolicy());
        vs.add(invalidVector("I01","CREATE sequence is 2 instead of 1","INVALID_SEQUENCE",i01));

        byte[] i02=rawCreateOperation(TestKeys.IDENTITY,1,v02.stateHash(),v02.controllerPolicy());
        vs.add(invalidVector("I02","CREATE contains a previousStateHash","INVALID_PREVIOUS_STATE_HASH",i02));

        byte[] p03=rawThresholdPolicy(0,List.of(em,mm));
        vs.add(invalidVector("I03","Controller threshold is zero","INVALID_CONTROLLER_THRESHOLD",
                rawCreateOperation(TestKeys.IDENTITY,1,null,p03)));

        byte[] p04=rawThresholdPolicy(3,List.of(em,mm));
        vs.add(invalidVector("I04","Controller threshold exceeds VerificationMethod count","INVALID_CONTROLLER_THRESHOLD",
                rawCreateOperation(TestKeys.IDENTITY,1,null,p04)));

        var dup=OpenIdentityCbor.verificationMethod(TestKeys.ED25519_METHOD_ID,mc);
        byte[] p05=rawThresholdPolicy(2,List.of(em,dup));
        vs.add(invalidVector("I05","Duplicate Verification Method ID","DUPLICATE_VERIFICATION_METHOD",
                rawCreateOperation(TestKeys.IDENTITY,1,null,p05)));

        Map<String,Object>d=new LinkedHashMap<>();
        d.put("specification","OpenIdentity Cryptographic Agility");
        d.put("version","0.1");
        d.put("type","invalid-conformance-vectors");
        d.put("vectors",vs);
        writeJson("crypto-invalid-java.json",d);
        success("I01-I05 generated"); blankLine();
    }

    private static byte[] rawCreateOperation(byte[] identity,long sequence,byte[] previousStateHash,byte[] policy){
        var payload=new DeterministicCborWriter();payload.writeMapHeader(1);payload.writeUnsigned(1);payload.writeEncoded(policy);
        var c=new DeterministicCborWriter();c.writeMapHeader(6);
        c.writeUnsigned(1);c.writeUnsigned(1);c.writeUnsigned(2);c.writeUnsigned(1);
        c.writeUnsigned(3);c.writeByteString(identity);c.writeUnsigned(4);c.writeUnsigned(sequence);
        c.writeUnsigned(5);if(previousStateHash==null)c.writeNull();else c.writeByteString(previousStateHash);
        c.writeUnsigned(6);c.writeEncoded(payload.toByteArray());return c.toByteArray();
    }

    private static byte[] rawThresholdPolicy(int threshold,List<OpenIdentityCbor.EncodedVerificationMethod> methods){
        var sorted=new java.util.ArrayList<>(methods);
        sorted.sort((a,b)->compareUnsignedBytes(a.id(),b.id()));
        var c=new DeterministicCborWriter();c.writeMapHeader(3);
        c.writeUnsigned(1);c.writeUnsigned(2);c.writeUnsigned(2);c.writeUnsigned(threshold);
        c.writeUnsigned(3);c.writeArrayHeader(sorted.size());
        for(var m:sorted)c.writeEncoded(m.encoded());return c.toByteArray();
    }

    private static int compareUnsignedBytes(byte[] a,byte[] b){
        for(int i=0;i<Math.min(a.length,b.length);i++){
            int x=Byte.toUnsignedInt(a[i]),y=Byte.toUnsignedInt(b[i]);
            if(x!=y)return Integer.compare(x,y);
        }
        return Integer.compare(a.length,b.length);
    }

    private static Map<String,Object> invalidVector(String id,String description,String expectedError,byte[] operation){
        Map<String,Object>v=new LinkedHashMap<>();v.put("id",id);v.put("description",description);
        v.put("expectedError",expectedError);v.put("operationBytesHex",Hex.encode(operation));return v;
    }


    private static void generateInvalidVectorsI06ToI20(HybridCreateResult v02) {
        var oldEd = new Ed25519Support(TestKeys.ED25519_SEED);
        var oldMl = new MlDsa65Support(TestKeys.ML_DSA_SEED);
        var newEd = new Ed25519Support(TestKeys.ED25519_SEED_B);
        var newMl = new MlDsa65Support(TestKeys.ML_DSA_SEED_B);

        var oldEdMethod = OpenIdentityCbor.verificationMethod(TestKeys.ED25519_METHOD_ID,
                OpenIdentityCbor.ed25519CoseKey(oldEd.publicKey()));
        var oldMlMethod = OpenIdentityCbor.verificationMethod(TestKeys.ML_DSA_METHOD_ID,
                OpenIdentityCbor.mlDsa65CoseKey(oldMl.publicKey()));
        byte[] oldPolicy = OpenIdentityCbor.thresholdPolicy(2, List.of(oldEdMethod, oldMlMethod));
        byte[] createOp = OpenIdentityCbor.createOperation(TestKeys.IDENTITY, oldPolicy);
        byte[] createInput = OpenIdentityCbor.operationSigningInput(createOp);
        var edProof = OpenIdentityCbor.authorizationProof(TestKeys.ED25519_METHOD_ID, oldEd.sign(createInput));
        var mlProof = OpenIdentityCbor.authorizationProof(TestKeys.ML_DSA_METHOD_ID, oldMl.sign(createInput));

        var newEdMethod = OpenIdentityCbor.verificationMethod(TestKeys.ED25519_METHOD_ID_B,
                OpenIdentityCbor.ed25519CoseKey(newEd.publicKey()));
        var newMlMethod = OpenIdentityCbor.verificationMethod(TestKeys.ML_DSA_METHOD_ID_B,
                OpenIdentityCbor.mlDsa65CoseKey(newMl.publicKey()));
        byte[] newPolicy = OpenIdentityCbor.thresholdPolicy(2, List.of(newEdMethod, newMlMethod));
        byte[] rotate = OpenIdentityCbor.rotateControllerOperation(TestKeys.IDENTITY, 2, v02.stateHash(), newPolicy);
        byte[] authIn = OpenIdentityCbor.operationSigningInput(rotate);
        var oldEdRot = OpenIdentityCbor.authorizationProof(TestKeys.ED25519_METHOD_ID, oldEd.sign(authIn));
        var oldMlRot = OpenIdentityCbor.authorizationProof(TestKeys.ML_DSA_METHOD_ID, oldMl.sign(authIn));
        byte[] ePopIn = OpenIdentityCbor.controllerProofSigningInput(rotate, TestKeys.ED25519_METHOD_ID_B);
        byte[] mPopIn = OpenIdentityCbor.controllerProofSigningInput(rotate, TestKeys.ML_DSA_METHOD_ID_B);
        var ePop = OpenIdentityCbor.controllerProof(TestKeys.ED25519_METHOD_ID_B, newEd.sign(ePopIn));
        var mPop = OpenIdentityCbor.controllerProof(TestKeys.ML_DSA_METHOD_ID_B, newMl.sign(mPopIn));

        List<Map<String,Object>> vs = new java.util.ArrayList<>();
        vs.add(invalidSigned("I06","Missing Ed25519 authorization proof","CONTROLLER_THRESHOLD_NOT_SATISFIED",
                createOp,rawSignedOperation(createOp,List.of(mlProof),List.of())));
        vs.add(invalidSigned("I07","Duplicate authorization proof","DUPLICATE_PROOF",
                createOp,rawSignedOperation(createOp,List.of(edProof,edProof),List.of())));

        byte[] badEd = oldEd.sign(createInput); badEd[0] ^= 1;
        vs.add(invalidSigned("I08","Corrupted Ed25519 authorization signature","INVALID_SIGNATURE",createOp,
                rawSignedOperation(createOp,List.of(OpenIdentityCbor.authorizationProof(TestKeys.ED25519_METHOD_ID,badEd),mlProof),List.of())));
        byte[] badMl = oldMl.sign(createInput); badMl[0] ^= 1;
        vs.add(invalidSigned("I09","Corrupted ML-DSA-65 authorization signature","INVALID_SIGNATURE",createOp,
                rawSignedOperation(createOp,List.of(edProof,OpenIdentityCbor.authorizationProof(TestKeys.ML_DSA_METHOD_ID,badMl)),List.of())));

        byte[] uid = Hex.decode("808182838485868788898a8b8c8d8e8f");
        var up = OpenIdentityCbor.authorizationProof(uid, oldEd.sign(createInput));
        vs.add(invalidSigned("I10","Unauthorized Verification Method ID","UNAUTHORIZED_VERIFICATION_METHOD",
                createOp,rawSignedOperation(createOp,List.of(edProof,mlProof,up),List.of())));

        byte[] wrongHash=Arrays.copyOf(v02.stateHash(),34); wrongHash[33]^=1;
        vs.add(invalidOperationOnly("I11","Incorrect previousStateHash","INVALID_PREVIOUS_STATE_HASH",
                OpenIdentityCbor.rotateControllerOperation(TestKeys.IDENTITY,2,wrongHash,newPolicy)));
        vs.add(invalidOperationOnly("I12","ROTATE sequence is not current + 1","INVALID_SEQUENCE",
                rawRotateOperation(TestKeys.IDENTITY,3,v02.stateHash(),newPolicy)));

        vs.add(invalidSigned("I13","New Ed25519 key missing PoP","MISSING_PROOF_OF_POSSESSION",rotate,
                rawSignedOperation(rotate,List.of(oldEdRot,oldMlRot),List.of(mPop))));
        vs.add(invalidSigned("I14","New ML-DSA key missing PoP","MISSING_PROOF_OF_POSSESSION",rotate,
                rawSignedOperation(rotate,List.of(oldEdRot,oldMlRot),List.of(ePop))));

        var wrongDomain=OpenIdentityCbor.controllerProof(TestKeys.ED25519_METHOD_ID_B,newEd.sign(authIn));
        vs.add(invalidSigned("I15","PoP uses authorization domain","INVALID_PROOF_OF_POSSESSION",rotate,
                rawSignedOperation(rotate,List.of(oldEdRot,oldMlRot),List.of(wrongDomain,mPop))));
        var wrongBound=OpenIdentityCbor.controllerProof(TestKeys.ML_DSA_METHOD_ID_B,newEd.sign(ePopIn));
        vs.add(invalidSigned("I16","PoP bound to wrong method ID","INVALID_PROOF_OF_POSSESSION",rotate,
                rawSignedOperation(rotate,List.of(oldEdRot,oldMlRot),List.of(ePop,wrongBound))));

        var selfE=OpenIdentityCbor.authorizationProof(TestKeys.ED25519_METHOD_ID_B,newEd.sign(authIn));
        var selfM=OpenIdentityCbor.authorizationProof(TestKeys.ML_DSA_METHOD_ID_B,newMl.sign(authIn));
        vs.add(invalidSigned("I17","New controller self-authorizes rotation","CONTROLLER_THRESHOLD_NOT_SATISFIED",rotate,
                rawSignedOperation(rotate,List.of(selfE,selfM),List.of(ePop,mPop))));

        var unsupported=OpenIdentityCbor.verificationMethod(Hex.decode("909192939495969798999a9b9c9d9e9f"),rawUnsupportedCoseKey());
        byte[] unsupportedPolicy=rawThresholdPolicy(1,List.of(unsupported));
        vs.add(invalidOperationOnly("I18","Unsupported algorithm","UNSUPPORTED_ALGORITHM",
                rawCreateOperation(TestKeys.IDENTITY,1,null,unsupportedPolicy)));
        vs.add(invalidOperationOnly("I19","Unknown signed map field","UNSUPPORTED_PROTOCOL_FEATURE",
                rawCreateWithUnknownField(TestKeys.IDENTITY,oldPolicy)));
        vs.add(invalidOperationOnly("I20","RECOVER is allocated but unsupported","UNSUPPORTED_OPERATION",
                rawRecoverOperation(TestKeys.IDENTITY,2,v02.stateHash())));

        Map<String,Object>d=new LinkedHashMap<>();
        d.put("specification","OpenIdentity Cryptographic Agility"); d.put("version","0.1");
        d.put("type","invalid-conformance-vectors-i06-i20"); d.put("vectors",vs);
        writeJson("crypto-invalid-i06-i20-java.json",d);
    }

    private static Map<String,Object> invalidSigned(String id,String desc,String error,byte[] op,byte[] signed){
        Map<String,Object>v=invalidVector(id,desc,error,op);v.put("signedOperationHex",Hex.encode(signed));return v;
    }
    private static Map<String,Object> invalidOperationOnly(String id,String desc,String error,byte[] op){
        return invalidVector(id,desc,error,op);
    }
    private static byte[] rawSignedOperation(byte[] op,List<OpenIdentityCbor.EncodedProof> auth,List<OpenIdentityCbor.EncodedProof> pop){
        var c=new DeterministicCborWriter();c.writeMapHeader(pop.isEmpty()?2:3);
        c.writeUnsigned(1);c.writeEncoded(op);c.writeUnsigned(2);c.writeArrayHeader(auth.size());
        for(var p:auth)c.writeEncoded(p.encoded());
        if(!pop.isEmpty()){c.writeUnsigned(3);c.writeArrayHeader(pop.size());for(var p:pop)c.writeEncoded(p.encoded());}
        return c.toByteArray();
    }
    private static byte[] rawRotateOperation(byte[] id,long seq,byte[] prev,byte[] policy){
        var p=new DeterministicCborWriter();p.writeMapHeader(1);p.writeUnsigned(1);p.writeEncoded(policy);
        var c=new DeterministicCborWriter();c.writeMapHeader(6);c.writeUnsigned(1);c.writeUnsigned(1);c.writeUnsigned(2);c.writeUnsigned(2);
        c.writeUnsigned(3);c.writeByteString(id);c.writeUnsigned(4);c.writeUnsigned(seq);c.writeUnsigned(5);c.writeByteString(prev);
        c.writeUnsigned(6);c.writeEncoded(p.toByteArray());return c.toByteArray();
    }
    private static byte[] rawUnsupportedCoseKey(){
        var c=new DeterministicCborWriter();c.writeMapHeader(2);c.writeUnsigned(1);c.writeUnsigned(7);c.writeUnsigned(3);c.writeSigned(-999);return c.toByteArray();
    }
    private static byte[] rawCreateWithUnknownField(byte[] id,byte[] policy){
        var p=new DeterministicCborWriter();p.writeMapHeader(1);p.writeUnsigned(1);p.writeEncoded(policy);
        var c=new DeterministicCborWriter();c.writeMapHeader(7);c.writeUnsigned(1);c.writeUnsigned(1);c.writeUnsigned(2);c.writeUnsigned(1);
        c.writeUnsigned(3);c.writeByteString(id);c.writeUnsigned(4);c.writeUnsigned(1);c.writeUnsigned(5);c.writeNull();
        c.writeUnsigned(6);c.writeEncoded(p.toByteArray());c.writeUnsigned(99);c.writeUnsigned(1);return c.toByteArray();
    }
    private static byte[] rawRecoverOperation(byte[] id,long seq,byte[] prev){
        var p=new DeterministicCborWriter();p.writeMapHeader(0);var c=new DeterministicCborWriter();c.writeMapHeader(6);
        c.writeUnsigned(1);c.writeUnsigned(1);c.writeUnsigned(2);c.writeUnsigned(3);c.writeUnsigned(3);c.writeByteString(id);
        c.writeUnsigned(4);c.writeUnsigned(seq);c.writeUnsigned(5);c.writeByteString(prev);c.writeUnsigned(6);c.writeEncoded(p.toByteArray());return c.toByteArray();
    }



    @SuppressWarnings("unchecked")
    private static void generateNormativeVectorFile(){
        section("NORMATIVE","Consolidating OI-002 conformance vectors");
        try{
            Path root=Path.of("..","..").toAbsolutePath().normalize();
            Path gen=root.resolve("test-vectors").resolve("generated");
            Path tv=root.resolve("test-vectors");
            ObjectMapper mapper=new ObjectMapper();

            List<Map<String,Object>> valid=new java.util.ArrayList<>();
            for(String name:List.of("crypto-v01-java.json","crypto-v02-java.json","crypto-v03-java.json","crypto-v04-java.json")){
                Map<String,Object>d=mapper.readValue(gen.resolve(name).toFile(),Map.class);
                valid.add((Map<String,Object>)d.get("vector"));
            }
            List<String> validIds=valid.stream().map(v->(String)v.get("id")).toList();
            if(!validIds.equals(List.of("V01","V02","V03","V04")))
                throw new IllegalStateException("Unexpected valid vector IDs: "+validIds);

            Map<String,Object>idoc=mapper.readValue(gen.resolve("crypto-invalid-java.json").toFile(),Map.class);
            List<Map<String,Object>> invalid=(List<Map<String,Object>>)idoc.get("vectors");
            List<String> expected=java.util.stream.IntStream.rangeClosed(1,20)
                    .mapToObj(i->String.format("I%02d",i)).toList();
            List<String> actual=invalid.stream().map(v->(String)v.get("id")).toList();
            if(!actual.equals(expected))throw new IllegalStateException("Unexpected invalid vector IDs: "+actual);

            Map<String,Object>ed=new LinkedHashMap<>();
            ed.put("coseKeyType",1);ed.put("coseAlgorithm",-8);ed.put("coseCurve",6);
            ed.put("publicKeyLength",32);ed.put("signatureLength",64);
            Map<String,Object>ml=new LinkedHashMap<>();
            ml.put("coseKeyType",7);ml.put("coseAlgorithm",-49);
            ml.put("publicKeyLength",1952);ml.put("signatureLength",3309);
            Map<String,Object>algorithms=new LinkedHashMap<>();
            algorithms.put("Ed25519",ed);algorithms.put("ML-DSA-65",ml);

            Map<String,Object>stateHash=new LinkedHashMap<>();
            stateHash.put("multihashAlgorithm","sha2-256");stateHash.put("multihashCode",18);
            stateHash.put("digestLength",32);stateHash.put("multihashLength",34);

            Map<String,Object>norm=new LinkedHashMap<>();
            norm.put("specification","OpenIdentity Cryptographic Agility");
            norm.put("version","0.1");norm.put("wireProtocolVersion",1);
            norm.put("identityStateVersion",1);norm.put("algorithms",algorithms);
            norm.put("stateHash",stateHash);norm.put("valid",valid);norm.put("invalid",invalid);

            ObjectMapper output=new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
            output.writeValue(tv.resolve("cryptographic-agility-v0.1.json").toFile(),norm);
            success("V01-V04 consolidated");success("I01-I20 consolidated");
            success("cryptographic-agility-v0.1.json");blankLine();
        }catch(IOException e){
            throw new IllegalStateException("Unable to generate normative OI-002 vector file",e);
        }
    }

    private static void section(String id,String description){
        System.out.println("["+id+"] "+description);
    }
    private static void success(String message){
        System.out.println("      [OK] "+message);
    }
    private static void blankLine(){
        System.out.println();
    }

    private static Map<String,Object> doc(Map<String,Object> v){Map<String,Object>d=new LinkedHashMap<>();d.put("specification","OpenIdentity Cryptographic Agility");d.put("version","0.1");d.put("vector",v);return d;}
    private static void put(Map<String,Object>m,String k,byte[]v){m.put(k,Hex.encode(v));}
    private static void same(String n,byte[]a,byte[]b){if(!Arrays.equals(a,b))throw new IllegalStateException(n+" differs from V02");}
    private static void writeJson(String filename,Map<String,Object> document){
        try{
            Path root=Path.of("..","..").toAbsolutePath().normalize(),dir=root.resolve("test-vectors").resolve("generated");Files.createDirectories(dir);
            ObjectMapper mapper=new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);Path file=dir.resolve(filename);mapper.writeValue(file.toFile(),document);
            System.out.println("Generated JSON:\n"+file+"\n");
        }catch(IOException e){throw new IllegalStateException("Unable to write generated vector JSON",e);}
    }
}
