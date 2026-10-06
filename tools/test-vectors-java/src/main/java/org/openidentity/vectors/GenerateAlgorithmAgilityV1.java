package org.openidentity.vectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.nio.file.*;
import java.util.*;

public final class GenerateAlgorithmAgilityV1 {
    private static final ObjectMapper JSON=new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private GenerateAlgorithmAgilityV1(){}

    public static void main(String[] args)throws Exception{
        byte[] op=OpenIdentityCbor.createOperation(TestKeys.IDENTITY,
                OpenIdentityCbor.singlePolicy(OpenIdentityCbor.verificationMethod(
                        TestKeys.ML_DSA_METHOD_ID,
                        OpenIdentityCbor.mlDsa65CoseKey(new MlDsa65Support(TestKeys.ML_DSA_SEED).publicKey()))));
        var ml=new MlDsa65Support(TestKeys.ML_DSA_SEED);
        var ed=new Ed25519Support(TestKeys.ED25519_SEED);
        var valid=new ArrayList<Map<String,Object>>();

        valid.add(single("ML01","Ed25519","Controller authorization",TestKeys.ED25519_METHOD_ID,ed.publicKey(),OpenIdentityCbor.operationSigningInput(op),ed.sign(OpenIdentityCbor.operationSigningInput(op))));
        valid.add(single("ML02","ML-DSA-65","Controller authorization",TestKeys.ML_DSA_METHOD_ID,ml.publicKey(),OpenIdentityCbor.operationSigningInput(op),ml.sign(OpenIdentityCbor.operationSigningInput(op))));

        byte[] common=OpenIdentityCbor.operationSigningInput(op);
        valid.add(mixed("ML03",2,op,common,ed,ml));
        valid.add(mixed("ML04",1,op,common,ed,ml));

        valid.add(mlPurpose("ML05","Controller PoP",op,TestKeys.ML_DSA_METHOD_ID,ml,OpenIdentityCbor.controllerProofSigningInput(op,TestKeys.ML_DSA_METHOD_ID)));
        valid.add(mlPurpose("ML06","Recovery authorization",op,TestKeys.ML_DSA_METHOD_ID,ml,OpenIdentityCbor.recoveryProofSigningInput(op,TestKeys.ML_DSA_METHOD_ID)));
        valid.add(mlPurpose("ML07","Authentication PoP",op,TestKeys.ML_DSA_METHOD_ID,ml,OpenIdentityCbor.authenticationProofSigningInput(op,TestKeys.ML_DSA_METHOD_ID)));
        valid.add(mlPurpose("ML08","Assertion PoP",op,TestKeys.ML_DSA_METHOD_ID,ml,OpenIdentityCbor.assertionProofSigningInput(op,TestKeys.ML_DSA_METHOD_ID)));
        valid.add(mlPurpose("ML09","Delegation PoP",op,TestKeys.ML_DSA_METHOD_ID,ml,OpenIdentityCbor.delegationProofSigningInput(op,TestKeys.ML_DSA_METHOD_ID)));

        var invalid=new ArrayList<Map<String,Object>>();
        var good=(Map<String,Object>)valid.get(1);byte[] sig=Hex.decode((String)good.get("signatureHex"));sig[0]^=1;
        invalid.add(invalidFrom(good,"MLI01","INVALID_SIGNATURE",sig));
        byte[] wrong=ml.sign(OpenIdentityCbor.assertionProofSigningInput(op,TestKeys.ML_DSA_METHOD_ID));
        var mli02=mlPurpose("MLI02","wrong-domain Authentication PoP",op,TestKeys.ML_DSA_METHOD_ID,ml,OpenIdentityCbor.authenticationProofSigningInput(op,TestKeys.ML_DSA_METHOD_ID));
        mli02.put("expected","REJECT");mli02.put("expectedError","INVALID_PROOF_OF_POSSESSION");mli02.put("signatureHex",Hex.encode(wrong));invalid.add(mli02);
        var mli03=mlPurpose("MLI03","unauthorized method",op,TestKeys.ML_DSA_METHOD_ID_B,ml,OpenIdentityCbor.authenticationProofSigningInput(op,TestKeys.ML_DSA_METHOD_ID_B));
        mli03.put("expected","REJECT");mli03.put("expectedError","UNAUTHORIZED_METHOD");mli03.put("authorizedMethodIdHex",Hex.encode(TestKeys.ML_DSA_METHOD_ID));invalid.add(mli03);
        byte[] trunc=Arrays.copyOf(ml.sign(common),3308);invalid.add(invalidFrom(good,"MLI04","INVALID_SIGNATURE",trunc));
        invalid.add(Map.of("id","MLI05","expected","REJECT","expectedError","MALFORMED_COSE_KEY","algorithm","ML-DSA-65","publicKeyHex","00".repeat(1951)));
        var insufficient=mixed("MLI06",2,op,common,ed,ml);insufficient.put("expected","REJECT");insufficient.put("expectedError","INSUFFICIENT_THRESHOLD");((List<?>)insufficient.get("proofs")).remove(1);invalid.add(insufficient);
        invalid.add(Map.of("id","MLI07","expected","REJECT","expectedError","DUPLICATE_EFFECTIVE_VERIFICATION_KEY","methodId1Hex",Hex.encode(TestKeys.ML_DSA_METHOD_ID),"methodId2Hex",Hex.encode(TestKeys.ML_DSA_METHOD_ID_B),"publicKeyHex",Hex.encode(ml.publicKey())));
        invalid.add(Map.of("id","MLI08","expected","REJECT","expectedError","ALGORITHM_KEY_MISMATCH","declaredAlgorithm","Ed25519","actualAlgorithm","ML-DSA-65","publicKeyHex",Hex.encode(ml.publicKey())));

        var root=new LinkedHashMap<String,Object>();
        root.put("specification","OpenIdentity cryptographic agility v1");
        root.put("status","DRAFT-NON-NORMATIVE");
        root.put("normativeCrypto","FIPS 204 ML-DSA-65");
        root.put("operationBytesHex",Hex.encode(op));
        root.put("validVectors",valid);root.put("invalidVectors",invalid);
        Path out=Path.of("../../test-vectors/generated/algorithm-agility-v1.json").normalize();
        JSON.writeValue(out.toFile(),root);
        System.out.println("OPENIDENTITY ALGORITHM AGILITY V1: GENERATED");
        System.out.println("Valid vectors: "+valid.size()+" / 9");
        System.out.println("Invalid vectors: "+invalid.size()+" / 8");
        System.out.println("ML-DSA-65 public key bytes: "+ml.publicKey().length);
        System.out.println("ML-DSA-65 signature bytes: "+ml.sign(common).length);
        System.out.println(out.toAbsolutePath());
    }

    static Map<String,Object> single(String id,String alg,String purpose,byte[] mid,byte[] pk,byte[] msg,byte[] sig){
        var m=new LinkedHashMap<String,Object>();m.put("id",id);m.put("expected","PASS");m.put("algorithm",alg);m.put("purpose",purpose);m.put("methodIdHex",Hex.encode(mid));m.put("publicKeyHex",Hex.encode(pk));m.put("signingBytesHex",Hex.encode(msg));m.put("signatureHex",Hex.encode(sig));return m;
    }
    static Map<String,Object> mlPurpose(String id,String purpose,byte[] op,byte[] mid,MlDsa65Support ml,byte[] msg){
        byte[] sig=ml.sign(msg);if(!ml.verify(msg,sig))throw new IllegalStateException(id+" ML-DSA verify");
        var m=single(id,"ML-DSA-65",purpose,mid,ml.publicKey(),msg,sig);m.put("operationBytesHex",Hex.encode(op));return m;
    }
    static Map<String,Object> mixed(String id,int threshold,byte[] op,byte[] msg,Ed25519Support ed,MlDsa65Support ml){
        byte[] es=ed.sign(msg),ms=ml.sign(msg);if(!ed.verify(msg,es)||!ml.verify(msg,ms))throw new IllegalStateException(id+" mixed verify");
        var m=new LinkedHashMap<String,Object>();m.put("id",id);m.put("expected","PASS");m.put("purpose","mixed Controller authorization");m.put("threshold",threshold);m.put("operationBytesHex",Hex.encode(op));m.put("signingBytesHex",Hex.encode(msg));
        var proofs=new ArrayList<Map<String,Object>>();proofs.add(Map.of("algorithm","Ed25519","methodIdHex",Hex.encode(TestKeys.ED25519_METHOD_ID),"publicKeyHex",Hex.encode(ed.publicKey()),"signatureHex",Hex.encode(es)));proofs.add(Map.of("algorithm","ML-DSA-65","methodIdHex",Hex.encode(TestKeys.ML_DSA_METHOD_ID),"publicKeyHex",Hex.encode(ml.publicKey()),"signatureHex",Hex.encode(ms)));m.put("proofs",proofs);return m;
    }
    static Map<String,Object> invalidFrom(Map<String,Object> base,String id,String err,byte[] sig){var m=new LinkedHashMap<>(base);m.put("id",id);m.put("expected","REJECT");m.put("expectedError",err);m.put("signatureHex",Hex.encode(sig));return m;}
}
