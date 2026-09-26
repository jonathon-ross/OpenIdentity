package org.openidentity.vectors;

import com.fasterxml.jackson.databind.*;

import java.io.IOException;
import java.security.MessageDigest;
import java.nio.file.*;
import java.util.*;

public final class GenerateVectors {
    private GenerateVectors() {
    }

    private record HybridCreateResult(byte[] controllerPolicy, byte[] operation, byte[] signingInput,
                                      byte[] signedOperation, byte[] identityState, byte[] stateHash) {
    }

    private record AssertionStateResult(byte[] assertionPolicy, byte[] identityState, byte[] stateHash) {
    }

    public static void main(String[] args) {
        System.out.println();
        System.out.println("OpenIdentity Cryptographic Test Vector Generator");
        System.out.println("================================================");
        System.out.println();
        generateV01();
        HybridCreateResult v02 = generateV02();
        generateV03(v02);
        generateV04(v02);
        generateAllInvalidVectors(v02);
        generateNormativeVectorFile();
        AssertionStateResult a01 = generateA01(v02);
        AssertionStateResult a02 = generateA02(v02, a01);
        AssertionStateResult a03 = generateA03(v02, a02);
        AssertionStateResult a04 = generateA04(v02, a03);
        generateAssertionInvalidVectors(v02, a01, a02, a03);
        generateNormativeAssertionAuthorityFile();
        generateC01(a01);
        generateC02(a04);
        generateCredentialInvalidVectors(a01, a03, a04);
        generateNormativeCredentialFile();
        generateW3cCredentialProjectionVectors();
        generateW3cCredentialProjectionInvalidVectors();
        generateNormativeW3cCredentialProjectionFile();
        generateR01(v02);
        generateRecoveryInvalidVectors(v02);
        generateR02(v02, a04);
        generateNormativeRecoveryFile();
        generateSignatureEnvelopeVectors(v02);
        generateNormativeSignatureEnvelopeFile();
        generateStateHashVectors(v02, a04);
        generateNormativeStateHashFile();
        System.out.println("================================================");
        System.out.println("ALL JAVA TEST VECTORS GENERATED SUCCESSFULLY");
        System.out.println("================================================");
    }

    private static void generateV01() {
        var ed = new Ed25519Support(TestKeys.ED25519_SEED);
        byte[] pk = ed.publicKey(), ck = OpenIdentityCbor.ed25519CoseKey(pk);
        var vm = OpenIdentityCbor.verificationMethod(TestKeys.ED25519_METHOD_ID, ck);
        byte[] pol = OpenIdentityCbor.singlePolicy(vm);
        byte[] op = OpenIdentityCbor.createOperation(TestKeys.IDENTITY, pol), si = OpenIdentityCbor.operationSigningInput(op), sig = ed.sign(si);
        if (!ed.verify(si, sig)) throw new IllegalStateException("V01 Ed25519 verification failed");
        var proof = OpenIdentityCbor.authorizationProof(TestKeys.ED25519_METHOD_ID, sig);
        byte[] so = OpenIdentityCbor.signedOperation(op, List.of(proof));


        Map<String, Object> v01 = new LinkedHashMap<>();
        v01.put("id", "V01");
        v01.put("description", "SINGLE Ed25519 CREATE");
        put(v01, "identityHex", TestKeys.IDENTITY);
        put(v01, "ed25519MethodIdHex", TestKeys.ED25519_METHOD_ID);
        put(v01, "ed25519PublicKeyHex", pk);
        put(v01, "ed25519CoseKeyHex", ck);
        put(v01, "ed25519VerificationMethodHex", vm.encoded());
        put(v01, "controllerPolicyHex", pol);
        put(v01, "operationBytesHex", op);
        put(v01, "signingInputHex", si);
        put(v01, "ed25519SignatureHex", sig);
        put(v01, "ed25519AuthorizationProofHex", proof.encoded());
        put(v01, "signedOperationHex", so);
        v01.put("ed25519PublicKeyLength", pk.length);
        v01.put("ed25519SignatureLength", sig.length);

        writeJson(
                "crypto-v01-java.json",
                doc(v01));

        success("crypto-v01-java.json");

        success("V01 complete");
        blankLine();
    }

    private static HybridCreateResult generateV02() {
        section("V02", "Hybrid Ed25519 + ML-DSA-65 CREATE");
        var ed = new Ed25519Support(TestKeys.ED25519_SEED);
        var ml = new MlDsa65Support(TestKeys.ML_DSA_SEED);
        byte[] ep = ed.publicKey(), mp = ml.publicKey(), ec = OpenIdentityCbor.ed25519CoseKey(ep), mc = OpenIdentityCbor.mlDsa65CoseKey(mp);
        var em = OpenIdentityCbor.verificationMethod(TestKeys.ED25519_METHOD_ID, ec);
        var mm = OpenIdentityCbor.verificationMethod(TestKeys.ML_DSA_METHOD_ID, mc);
        byte[] pol = OpenIdentityCbor.thresholdPolicy(2, List.of(em, mm)), op = OpenIdentityCbor.createOperation(TestKeys.IDENTITY, pol), si = OpenIdentityCbor.operationSigningInput(op);
        byte[] es = ed.sign(si), ms = ml.sign(si);
        if (!ed.verify(si, es) || !ml.verify(si, ms))
            throw new IllegalStateException("V02 signature verification failed");
        var epr = OpenIdentityCbor.authorizationProof(TestKeys.ED25519_METHOD_ID, es);
        var mpr = OpenIdentityCbor.authorizationProof(TestKeys.ML_DSA_METHOD_ID, ms);
        byte[] so = OpenIdentityCbor.signedOperation(op, List.of(epr, mpr));
        byte[] state = OpenIdentityCbor.activeIdentityState(TestKeys.IDENTITY, 1, pol), hash = StateHash.sha256Multihash(state);

        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", "V02");
        v.put("description", "Hybrid Ed25519 + ML-DSA-65 CREATE");
        put(v, "identityHex", TestKeys.IDENTITY);
        put(v, "ed25519MethodIdHex", TestKeys.ED25519_METHOD_ID);
        put(v, "mlDsa65MethodIdHex", TestKeys.ML_DSA_METHOD_ID);
        put(v, "ed25519PublicKeyHex", ep);
        put(v, "mlDsa65PublicKeyHex", mp);
        put(v, "ed25519CoseKeyHex", ec);
        put(v, "mlDsa65CoseKeyHex", mc);
        put(v, "ed25519VerificationMethodHex", em.encoded());
        put(v, "mlDsa65VerificationMethodHex", mm.encoded());
        put(v, "controllerPolicyHex", pol);
        put(v, "operationBytesHex", op);
        put(v, "signingInputHex", si);
        put(v, "ed25519SignatureHex", es);
        put(v, "mlDsa65SignatureHex", ms);
        put(v, "ed25519AuthorizationProofHex", epr.encoded());
        put(v, "mlDsa65AuthorizationProofHex", mpr.encoded());
        put(v, "signedOperationHex", so);
        put(v, "identityStateHex", state);
        put(v, "stateHashHex", hash);
        v.put("ed25519PublicKeyLength", ep.length);
        v.put("mlDsa65PublicKeyLength", mp.length);
        v.put("ed25519SignatureLength", es.length);
        v.put("mlDsa65SignatureLength", ms.length);
        writeJson("crypto-v02-java.json", doc(v));

        success("Ed25519 signature verified");
        success("ML-DSA-65 signature verified");
        success("IdentityState and StateHash generated");
        success("crypto-v02-java.json");
        blankLine();
        return new HybridCreateResult(pol, op, si, so, state, hash);
    }

    private static void generateV03(HybridCreateResult v02) {
        section("V03", "Canonical Ordering");
        var ed = new Ed25519Support(TestKeys.ED25519_SEED);
        var ml = new MlDsa65Support(TestKeys.ML_DSA_SEED);
        var em = OpenIdentityCbor.verificationMethod(TestKeys.ED25519_METHOD_ID, OpenIdentityCbor.ed25519CoseKey(ed.publicKey()));
        var mm = OpenIdentityCbor.verificationMethod(TestKeys.ML_DSA_METHOD_ID, OpenIdentityCbor.mlDsa65CoseKey(ml.publicKey()));
        byte[] pol = OpenIdentityCbor.thresholdPolicy(2, List.of(mm, em)), op = OpenIdentityCbor.createOperation(TestKeys.IDENTITY, pol), si = OpenIdentityCbor.operationSigningInput(op);
        var ep = OpenIdentityCbor.authorizationProof(TestKeys.ED25519_METHOD_ID, ed.sign(si));
        var mp = OpenIdentityCbor.authorizationProof(TestKeys.ML_DSA_METHOD_ID, ml.sign(si));
        byte[] so = OpenIdentityCbor.signedOperation(op, List.of(mp, ep));
        same("ControllerPolicy", v02.controllerPolicy(), pol);
        same("OperationBytes", v02.operation(), op);
        same("SigningInput", v02.signingInput(), si);
        same("SignedOperation", v02.signedOperation(), so);
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", "V03");
        v.put("description", "Canonical ordering with reversed method and proof input");
        v.put("inputMethodOrder", List.of("ML-DSA-65", "Ed25519"));
        v.put("inputProofOrder", List.of("ML-DSA-65", "Ed25519"));
        put(v, "controllerPolicyHex", pol);
        put(v, "operationBytesHex", op);
        put(v, "signingInputHex", si);
        put(v, "signedOperationHex", so);
        v.put("matchesV02ControllerPolicy", true);
        v.put("matchesV02OperationBytes", true);
        v.put("matchesV02SigningInput", true);
        v.put("matchesV02SignedOperation", true);
        writeJson("crypto-v03-java.json", doc(v));
        success("Canonical outputs match V02");
        success("crypto-v03-java.json");
        blankLine();
    }


    private static void generateV04(HybridCreateResult v02) {
        section("V04", "ROTATE_CONTROLLER + Proof of Possession");

        var oldEd = new Ed25519Support(TestKeys.ED25519_SEED);
        var oldMl = new MlDsa65Support(TestKeys.ML_DSA_SEED);
        var newEd = new Ed25519Support(TestKeys.ED25519_SEED_B);
        var newMl = new MlDsa65Support(TestKeys.ML_DSA_SEED_B);

        byte[] newEdPk = newEd.publicKey(), newMlPk = newMl.publicKey();
        requireLength("new Ed25519 public key", newEdPk, 32);
        requireLength("new ML-DSA-65 public key", newMlPk, 1952);

        byte[] newEdCose = OpenIdentityCbor.ed25519CoseKey(newEdPk);
        byte[] newMlCose = OpenIdentityCbor.mlDsa65CoseKey(newMlPk);
        var newEdMethod = OpenIdentityCbor.verificationMethod(TestKeys.ED25519_METHOD_ID_B, newEdCose);
        var newMlMethod = OpenIdentityCbor.verificationMethod(TestKeys.ML_DSA_METHOD_ID_B, newMlCose);
        byte[] newPolicy = OpenIdentityCbor.thresholdPolicy(2, List.of(newEdMethod, newMlMethod));

        byte[] operation = OpenIdentityCbor.rotateControllerOperation(
                TestKeys.IDENTITY, 2, v02.stateHash(), newPolicy);

        byte[] authInput = OpenIdentityCbor.operationSigningInput(operation);
        byte[] oldEdSig = oldEd.sign(authInput), oldMlSig = oldMl.sign(authInput);
        if (!oldEd.verify(authInput, oldEdSig) || !oldMl.verify(authInput, oldMlSig))
            throw new IllegalStateException("V04 old-controller authorization failed");

        var oldEdProof = OpenIdentityCbor.authorizationProof(TestKeys.ED25519_METHOD_ID, oldEdSig);
        var oldMlProof = OpenIdentityCbor.authorizationProof(TestKeys.ML_DSA_METHOD_ID, oldMlSig);

        byte[] newEdPopInput = OpenIdentityCbor.controllerProofSigningInput(operation, TestKeys.ED25519_METHOD_ID_B);
        byte[] newEdPopSig = newEd.sign(newEdPopInput);
        if (!newEd.verify(newEdPopInput, newEdPopSig))
            throw new IllegalStateException("V04 new Ed25519 PoP failed");
        var newEdPop = OpenIdentityCbor.controllerProof(TestKeys.ED25519_METHOD_ID_B, newEdPopSig);

        byte[] newMlPopInput = OpenIdentityCbor.controllerProofSigningInput(operation, TestKeys.ML_DSA_METHOD_ID_B);
        byte[] newMlPopSig = newMl.sign(newMlPopInput);
        if (!newMl.verify(newMlPopInput, newMlPopSig))
            throw new IllegalStateException("V04 new ML-DSA-65 PoP failed");
        var newMlPop = OpenIdentityCbor.controllerProof(TestKeys.ML_DSA_METHOD_ID_B, newMlPopSig);

        byte[] signed = OpenIdentityCbor.signedOperation(
                operation, List.of(oldEdProof, oldMlProof), List.of(newEdPop, newMlPop));

        byte[] resultState = OpenIdentityCbor.activeIdentityState(TestKeys.IDENTITY, 2, newPolicy);
        byte[] resultHash = StateHash.sha256Multihash(resultState);
        if (Arrays.equals(v02.stateHash(), resultHash))
            throw new IllegalStateException("V04 resulting StateHash unexpectedly equals V02 StateHash");

        requireLength("old Ed25519 signature", oldEdSig, 64);
        requireLength("old ML-DSA-65 signature", oldMlSig, 3309);
        requireLength("new Ed25519 PoP signature", newEdPopSig, 64);
        requireLength("new ML-DSA-65 PoP signature", newMlPopSig, 3309);

        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", "V04");
        v.put("description", "Hybrid ROTATE_CONTROLLER with new-controller proof of possession");
        put(v, "identityHex", TestKeys.IDENTITY);
        v.put("sequence", 2);
        put(v, "previousIdentityStateHex", v02.identityState());
        put(v, "previousStateHashHex", v02.stateHash());

        put(v, "oldEd25519MethodIdHex", TestKeys.ED25519_METHOD_ID);
        put(v, "oldMlDsa65MethodIdHex", TestKeys.ML_DSA_METHOD_ID);
        put(v, "oldEd25519PublicKeyHex", oldEd.publicKey());
        put(v, "oldMlDsa65PublicKeyHex", oldMl.publicKey());

        put(v, "newEd25519MethodIdHex", TestKeys.ED25519_METHOD_ID_B);
        put(v, "newMlDsa65MethodIdHex", TestKeys.ML_DSA_METHOD_ID_B);
        put(v, "newEd25519PublicKeyHex", newEdPk);
        put(v, "newMlDsa65PublicKeyHex", newMlPk);
        put(v, "newEd25519CoseKeyHex", newEdCose);
        put(v, "newMlDsa65CoseKeyHex", newMlCose);
        put(v, "newEd25519VerificationMethodHex", newEdMethod.encoded());
        put(v, "newMlDsa65VerificationMethodHex", newMlMethod.encoded());
        put(v, "newControllerPolicyHex", newPolicy);

        put(v, "operationBytesHex", operation);
        put(v, "authorizationSigningInputHex", authInput);
        put(v, "oldEd25519AuthorizationSignatureHex", oldEdSig);
        put(v, "oldMlDsa65AuthorizationSignatureHex", oldMlSig);
        put(v, "oldEd25519AuthorizationProofHex", oldEdProof.encoded());
        put(v, "oldMlDsa65AuthorizationProofHex", oldMlProof.encoded());

        put(v, "newEd25519PopSigningInputHex", newEdPopInput);
        put(v, "newEd25519PopSignatureHex", newEdPopSig);
        put(v, "newEd25519ControllerProofHex", newEdPop.encoded());
        put(v, "newMlDsa65PopSigningInputHex", newMlPopInput);
        put(v, "newMlDsa65PopSignatureHex", newMlPopSig);
        put(v, "newMlDsa65ControllerProofHex", newMlPop.encoded());

        put(v, "signedOperationHex", signed);
        put(v, "resultingIdentityStateHex", resultState);
        put(v, "resultingStateHashHex", resultHash);
        v.put("oldControllerThreshold", 2);
        v.put("newControllerThreshold", 2);
        v.put("authorizationProofCount", 2);
        v.put("controllerProofCount", 2);
        v.put("oldEd25519SignatureLength", oldEdSig.length);
        v.put("oldMlDsa65SignatureLength", oldMlSig.length);
        v.put("newEd25519PopSignatureLength", newEdPopSig.length);
        v.put("newMlDsa65PopSignatureLength", newMlPopSig.length);

        writeJson("crypto-v04-java.json", doc(v));


        System.out.println("Old controller authorization: PASS");
        System.out.println("New controller proof of possession: PASS");
        success("Old controller authorization verified");
        success("New controller proof-of-possession verified");
        success("Resulting IdentityState and StateHash generated");
        success("crypto-v04-java.json");
        blankLine();
    }

    private static void requireLength(String name, byte[] value, int expected) {
        if (value == null || value.length != expected)
            throw new IllegalStateException(name + " length expected " + expected + " but got " + (value == null ? "null" : value.length));
    }


    /**
     * A01 -- first OI-003 state-transition vector.
     * <p>
     * Starting point:
     * frozen OI-002 V02 IdentityState v1
     * <p>
     * Transition:
     * SET_ASSERTION_POLICY
     * <p>
     * Authorization:
     * current V02 ControllerPolicy (Ed25519 + ML-DSA-65, threshold 2)
     * <p>
     * Proposed assertion authority:
     * SINGLE Ed25519 using the B test key/method ID
     * <p>
     * Result:
     * IdentityState v2, same identity and ControllerPolicy, sequence 2,
     * with AssertionPolicy at canonical state map label 7.
     */
    private static AssertionStateResult generateA01(HybridCreateResult v02) {
        section("A01", "v1 -> v2 SET_ASSERTION_POLICY with SINGLE Ed25519");

        var controllerEd = new Ed25519Support(TestKeys.ED25519_SEED);
        var controllerMl = new MlDsa65Support(TestKeys.ML_DSA_SEED);
        var assertionEd = new Ed25519Support(TestKeys.ED25519_SEED_B);

        byte[] assertionPk = assertionEd.publicKey();
        requireLength("A01 assertion Ed25519 public key", assertionPk, 32);

        byte[] assertionCose = OpenIdentityCbor.ed25519CoseKey(assertionPk);
        var assertionMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID_B,
                assertionCose);
        byte[] assertionPolicy = OpenIdentityCbor.singlePolicy(assertionMethod);

        byte[] operation = OpenIdentityCbor.setAssertionPolicyOperation(
                TestKeys.IDENTITY,
                2,
                v02.stateHash(),
                assertionPolicy);

        // The CURRENT v1 ControllerPolicy authorizes the transition.
        byte[] authInput = OpenIdentityCbor.operationSigningInput(operation);
        byte[] controllerEdSig = controllerEd.sign(authInput);
        byte[] controllerMlSig = controllerMl.sign(authInput);

        if (!controllerEd.verify(authInput, controllerEdSig)
                || !controllerMl.verify(authInput, controllerMlSig)) {
            throw new IllegalStateException(
                    "A01 current-controller authorization failed");
        }

        var controllerEdProof = OpenIdentityCbor.authorizationProof(
                TestKeys.ED25519_METHOD_ID,
                controllerEdSig);
        var controllerMlProof = OpenIdentityCbor.authorizationProof(
                TestKeys.ML_DSA_METHOD_ID,
                controllerMlSig);

        // The proposed assertion key separately proves possession.
        byte[] assertionPopInput =
                OpenIdentityCbor.controllerProofSigningInput(
                        operation,
                        TestKeys.ED25519_METHOD_ID_B);
        byte[] assertionPopSig = assertionEd.sign(assertionPopInput);

        if (!assertionEd.verify(assertionPopInput, assertionPopSig)) {
            throw new IllegalStateException(
                    "A01 assertion-key proof of possession failed");
        }

        var assertionPop = OpenIdentityCbor.controllerProof(
                TestKeys.ED25519_METHOD_ID_B,
                assertionPopSig);

        byte[] signed = OpenIdentityCbor.signedOperation(
                operation,
                List.of(controllerEdProof, controllerMlProof),
                List.of(assertionPop));

        byte[] resultState = OpenIdentityCbor.activeIdentityStateV2(
                TestKeys.IDENTITY,
                2,
                v02.controllerPolicy(),
                assertionPolicy);
        byte[] resultHash = StateHash.sha256Multihash(resultState);

        if (Arrays.equals(v02.stateHash(), resultHash)) {
            throw new IllegalStateException(
                    "A01 resulting v2 StateHash unexpectedly equals V02 v1 StateHash");
        }

        requireLength("A01 controller Ed25519 signature", controllerEdSig, 64);
        requireLength("A01 controller ML-DSA-65 signature", controllerMlSig, 3309);
        requireLength("A01 assertion Ed25519 PoP signature", assertionPopSig, 64);
        requireLength("A01 resulting StateHash", resultHash, 34);

        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", "A01");
        v.put("description",
                "SET_ASSERTION_POLICY upgrades IdentityState v1 to v2 with SINGLE Ed25519 assertion authority");

        put(v, "identityHex", TestKeys.IDENTITY);
        v.put("sourceVector", "V02");
        v.put("previousIdentityStateVersion", 1);
        v.put("resultingIdentityStateVersion", 2);
        v.put("sequence", 2);

        put(v, "previousIdentityStateHex", v02.identityState());
        put(v, "previousStateHashHex", v02.stateHash());
        put(v, "controllerPolicyHex", v02.controllerPolicy());

        put(v, "assertionEd25519MethodIdHex", TestKeys.ED25519_METHOD_ID_B);
        put(v, "assertionEd25519PublicKeyHex", assertionPk);
        put(v, "assertionEd25519CoseKeyHex", assertionCose);
        put(v, "assertionEd25519VerificationMethodHex", assertionMethod.encoded());
        put(v, "assertionPolicyHex", assertionPolicy);
        v.put("assertionPolicyType", "SINGLE");
        v.put("assertionThreshold", 1);

        put(v, "operationBytesHex", operation);
        put(v, "authorizationSigningInputHex", authInput);
        put(v, "controllerEd25519AuthorizationSignatureHex", controllerEdSig);
        put(v, "controllerMlDsa65AuthorizationSignatureHex", controllerMlSig);
        put(v, "controllerEd25519AuthorizationProofHex",
                controllerEdProof.encoded());
        put(v, "controllerMlDsa65AuthorizationProofHex",
                controllerMlProof.encoded());

        put(v, "assertionEd25519PopSigningInputHex", assertionPopInput);
        put(v, "assertionEd25519PopSignatureHex", assertionPopSig);
        put(v, "assertionEd25519ProofOfPossessionHex", assertionPop.encoded());

        put(v, "signedOperationHex", signed);
        put(v, "resultingIdentityStateHex", resultState);
        put(v, "resultingStateHashHex", resultHash);

        v.put("authorizationProofCount", 2);
        v.put("assertionProofOfPossessionCount", 1);
        v.put("controllerEd25519SignatureLength", controllerEdSig.length);
        v.put("controllerMlDsa65SignatureLength", controllerMlSig.length);
        v.put("assertionEd25519PopSignatureLength", assertionPopSig.length);
        v.put("stateHashLength", resultHash.length);

        Map<String, Object> d = new LinkedHashMap<>();
        d.put("specification", "OpenIdentity Assertion Authority");
        d.put("version", "0.1");
        d.put("wireProtocolVersion", 1);
        d.put("sourceIdentityStateVersion", 1);
        d.put("resultingIdentityStateVersion", 2);
        d.put("vector", v);

        writeJson("assertion-a01-java.json", d);

        success("Current V02 ControllerPolicy authorization verified");
        success("New assertion Ed25519 proof-of-possession verified");
        success("IdentityState upgraded from v1 to v2");
        success("ControllerPolicy preserved");
        success("SINGLE Ed25519 AssertionPolicy installed");
        success("Resulting v2 IdentityState and StateHash generated");
        success("assertion-a01-java.json");
        blankLine();
        return new AssertionStateResult(assertionPolicy, resultState, resultHash);
    }


    private static AssertionStateResult generateA02(HybridCreateResult v02, AssertionStateResult a01) {
        section("A02", "v2 -> v2 replace SINGLE Ed25519 AssertionPolicy");

        var controllerEd = new Ed25519Support(TestKeys.ED25519_SEED);
        var controllerMl = new MlDsa65Support(TestKeys.ML_DSA_SEED);
        var assertionEd = new Ed25519Support(TestKeys.ED25519_SEED_C);

        byte[] assertionPk = assertionEd.publicKey();
        requireLength("A02 assertion Ed25519 public key", assertionPk, 32);

        byte[] assertionCose = OpenIdentityCbor.ed25519CoseKey(assertionPk);
        var assertionMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID_C, assertionCose);
        byte[] assertionPolicy = OpenIdentityCbor.singlePolicy(assertionMethod);

        if (Arrays.equals(a01.assertionPolicy(), assertionPolicy))
            throw new IllegalStateException("A02 assertion policy did not change");

        byte[] operation = OpenIdentityCbor.setAssertionPolicyOperation(
                TestKeys.IDENTITY, 3, a01.stateHash(), assertionPolicy);

        byte[] authInput = OpenIdentityCbor.operationSigningInput(operation);
        byte[] edSig = controllerEd.sign(authInput);
        byte[] mlSig = controllerMl.sign(authInput);
        if (!controllerEd.verify(authInput, edSig) || !controllerMl.verify(authInput, mlSig))
            throw new IllegalStateException("A02 controller authorization failed");

        var edProof = OpenIdentityCbor.authorizationProof(TestKeys.ED25519_METHOD_ID, edSig);
        var mlProof = OpenIdentityCbor.authorizationProof(TestKeys.ML_DSA_METHOD_ID, mlSig);

        byte[] popInput = OpenIdentityCbor.controllerProofSigningInput(
                operation, TestKeys.ED25519_METHOD_ID_C);
        byte[] popSig = assertionEd.sign(popInput);
        if (!assertionEd.verify(popInput, popSig))
            throw new IllegalStateException("A02 assertion-key PoP failed");
        var pop = OpenIdentityCbor.controllerProof(TestKeys.ED25519_METHOD_ID_C, popSig);

        byte[] signed = OpenIdentityCbor.signedOperation(
                operation, List.of(edProof, mlProof), List.of(pop));

        byte[] resultState = OpenIdentityCbor.activeIdentityStateV2(
                TestKeys.IDENTITY, 3, v02.controllerPolicy(), assertionPolicy);
        byte[] resultHash = StateHash.sha256Multihash(resultState);
        if (Arrays.equals(a01.stateHash(), resultHash))
            throw new IllegalStateException("A02 StateHash unexpectedly equals A01");

        requireLength("A02 controller Ed25519 signature", edSig, 64);
        requireLength("A02 controller ML-DSA-65 signature", mlSig, 3309);
        requireLength("A02 assertion Ed25519 PoP signature", popSig, 64);
        requireLength("A02 StateHash", resultHash, 34);

        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", "A02");
        v.put("description", "SET_ASSERTION_POLICY replaces SINGLE Ed25519 assertion authority while remaining IdentityState v2");
        put(v, "identityHex", TestKeys.IDENTITY);
        v.put("sourceVector", "A01");
        v.put("previousIdentityStateVersion", 2);
        v.put("resultingIdentityStateVersion", 2);
        v.put("sequence", 3);
        put(v, "previousIdentityStateHex", a01.identityState());
        put(v, "previousStateHashHex", a01.stateHash());
        put(v, "controllerPolicyHex", v02.controllerPolicy());
        put(v, "retiredAssertionEd25519MethodIdHex", TestKeys.ED25519_METHOD_ID_B);
        put(v, "previousAssertionPolicyHex", a01.assertionPolicy());
        put(v, "assertionEd25519MethodIdHex", TestKeys.ED25519_METHOD_ID_C);
        put(v, "assertionEd25519PublicKeyHex", assertionPk);
        put(v, "assertionEd25519CoseKeyHex", assertionCose);
        put(v, "assertionEd25519VerificationMethodHex", assertionMethod.encoded());
        put(v, "assertionPolicyHex", assertionPolicy);
        v.put("assertionPolicyType", "SINGLE");
        v.put("assertionThreshold", 1);
        put(v, "operationBytesHex", operation);
        put(v, "authorizationSigningInputHex", authInput);
        put(v, "controllerEd25519AuthorizationSignatureHex", edSig);
        put(v, "controllerMlDsa65AuthorizationSignatureHex", mlSig);
        put(v, "controllerEd25519AuthorizationProofHex", edProof.encoded());
        put(v, "controllerMlDsa65AuthorizationProofHex", mlProof.encoded());
        put(v, "assertionEd25519PopSigningInputHex", popInput);
        put(v, "assertionEd25519PopSignatureHex", popSig);
        put(v, "assertionEd25519ProofOfPossessionHex", pop.encoded());
        put(v, "signedOperationHex", signed);
        put(v, "resultingIdentityStateHex", resultState);
        put(v, "resultingStateHashHex", resultHash);
        v.put("authorizationProofCount", 2);
        v.put("assertionProofOfPossessionCount", 1);
        v.put("controllerEd25519SignatureLength", edSig.length);
        v.put("controllerMlDsa65SignatureLength", mlSig.length);
        v.put("assertionEd25519PopSignatureLength", popSig.length);
        v.put("stateHashLength", resultHash.length);
        v.put("controllerPolicyPreserved", true);
        v.put("retiredAssertionMethodRemoved", true);

        Map<String, Object> d = new LinkedHashMap<>();
        d.put("specification", "OpenIdentity Assertion Authority");
        d.put("version", "0.1");
        d.put("wireProtocolVersion", 1);
        d.put("sourceIdentityStateVersion", 2);
        d.put("resultingIdentityStateVersion", 2);
        d.put("vector", v);
        writeJson("assertion-a02-java.json", d);

        success("A01 StateHash used as previousStateHash");
        success("Current ControllerPolicy authorization verified");
        success("New assertion Ed25519 proof-of-possession verified");
        success("IdentityState remains v2");
        success("ControllerPolicy preserved");
        success("Old assertion method retired");
        success("New SINGLE Ed25519 AssertionPolicy installed");
        success("Resulting v2 IdentityState and StateHash generated");
        success("assertion-a02-java.json");
        blankLine();
        return new AssertionStateResult(assertionPolicy, resultState, resultHash);
    }


    /**
     * A03 -- remove assertion authority from an existing IdentityState v2.
     * <p>
     * SET_ASSERTION_POLICY carries nil as the replacement policy. The current
     * ControllerPolicy authorizes the transition. Because no new assertion
     * VerificationMethod is being installed, no proof of possession is
     * required and SignedOperation field 3 is omitted.
     */
    private static AssertionStateResult generateA03(
            HybridCreateResult v02,
            AssertionStateResult a02) {
        section("A03", "v2 -> v2 remove AssertionPolicy");

        var controllerEd = new Ed25519Support(TestKeys.ED25519_SEED);
        var controllerMl = new MlDsa65Support(TestKeys.ML_DSA_SEED);

        byte[] operation = OpenIdentityCbor.setAssertionPolicyOperation(
                TestKeys.IDENTITY,
                4,
                a02.stateHash(),
                null);

        byte[] authInput = OpenIdentityCbor.operationSigningInput(operation);
        byte[] edSig = controllerEd.sign(authInput);
        byte[] mlSig = controllerMl.sign(authInput);

        if (!controllerEd.verify(authInput, edSig)
                || !controllerMl.verify(authInput, mlSig)) {
            throw new IllegalStateException(
                    "A03 current-controller authorization failed");
        }

        var edProof = OpenIdentityCbor.authorizationProof(
                TestKeys.ED25519_METHOD_ID, edSig);
        var mlProof = OpenIdentityCbor.authorizationProof(
                TestKeys.ML_DSA_METHOD_ID, mlSig);

        // No proposed assertion keys exist, so field 3 MUST be absent.
        byte[] signed = OpenIdentityCbor.signedOperation(
                operation, List.of(edProof, mlProof));

        // null means field 7 is absent, not 7 => nil.
        byte[] resultState = OpenIdentityCbor.activeIdentityStateV2(
                TestKeys.IDENTITY,
                4,
                v02.controllerPolicy(),
                null);
        byte[] resultHash = StateHash.sha256Multihash(resultState);

        if (Arrays.equals(a02.stateHash(), resultHash)) {
            throw new IllegalStateException(
                    "A03 resulting StateHash unexpectedly equals A02 StateHash");
        }

        requireLength("A03 controller Ed25519 signature", edSig, 64);
        requireLength("A03 controller ML-DSA-65 signature", mlSig, 3309);
        requireLength("A03 StateHash", resultHash, 34);

        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", "A03");
        v.put("description",
                "SET_ASSERTION_POLICY removes assertion authority while remaining IdentityState v2");
        put(v, "identityHex", TestKeys.IDENTITY);
        v.put("sourceVector", "A02");
        v.put("previousIdentityStateVersion", 2);
        v.put("resultingIdentityStateVersion", 2);
        v.put("sequence", 4);

        put(v, "previousIdentityStateHex", a02.identityState());
        put(v, "previousStateHashHex", a02.stateHash());
        put(v, "controllerPolicyHex", v02.controllerPolicy());
        put(v, "removedAssertionEd25519MethodIdHex",
                TestKeys.ED25519_METHOD_ID_C);
        put(v, "previousAssertionPolicyHex", a02.assertionPolicy());

        v.put("assertionPolicy", null);

        put(v, "operationBytesHex", operation);
        put(v, "authorizationSigningInputHex", authInput);
        put(v, "controllerEd25519AuthorizationSignatureHex", edSig);
        put(v, "controllerMlDsa65AuthorizationSignatureHex", mlSig);
        put(v, "controllerEd25519AuthorizationProofHex", edProof.encoded());
        put(v, "controllerMlDsa65AuthorizationProofHex", mlProof.encoded());

        put(v, "signedOperationHex", signed);
        put(v, "resultingIdentityStateHex", resultState);
        put(v, "resultingStateHashHex", resultHash);

        v.put("authorizationProofCount", 2);
        v.put("assertionProofOfPossessionCount", 0);
        v.put("controllerEd25519SignatureLength", edSig.length);
        v.put("controllerMlDsa65SignatureLength", mlSig.length);
        v.put("stateHashLength", resultHash.length);
        v.put("controllerPolicyPreserved", true);
        v.put("assertionPolicyPresent", false);
        v.put("assertionAuthorityCount", 0);

        Map<String, Object> d = new LinkedHashMap<>();
        d.put("specification", "OpenIdentity Assertion Authority");
        d.put("version", "0.1");
        d.put("wireProtocolVersion", 1);
        d.put("sourceIdentityStateVersion", 2);
        d.put("resultingIdentityStateVersion", 2);
        d.put("vector", v);

        writeJson("assertion-a03-java.json", d);

        success("A02 StateHash used as previousStateHash");
        success("Current ControllerPolicy authorization verified");
        success("No assertion proof-of-possession required");
        success("IdentityState remains v2");
        success("ControllerPolicy preserved");
        success("AssertionPolicy removed");
        success("Resulting state has no assertion authority");
        success("Resulting v2 IdentityState and StateHash generated");
        success("assertion-a03-java.json");
        blankLine();
        return new AssertionStateResult(null, resultState, resultHash);
    }


    /**
     * A04 -- install hybrid THRESHOLD 2-of-2 assertion authority after A03.
     * <p>
     * The current ControllerPolicy authorizes the state transition.
     * Both proposed assertion methods independently prove possession.
     */
    private static AssertionStateResult generateA04(
            HybridCreateResult v02,
            AssertionStateResult a03) {
        section("A04", "v2 -> v2 install THRESHOLD 2-of-2 Ed25519 + ML-DSA-65 AssertionPolicy");

        var controllerEd = new Ed25519Support(TestKeys.ED25519_SEED);
        var controllerMl = new MlDsa65Support(TestKeys.ML_DSA_SEED);

        // Reuse the B test key pair as assertion authority. These method IDs
        // are distinct from the current controller method IDs.
        var assertionEd = new Ed25519Support(TestKeys.ED25519_SEED_B);
        var assertionMl = new MlDsa65Support(TestKeys.ML_DSA_SEED_B);

        byte[] edPk = assertionEd.publicKey();
        byte[] mlPk = assertionMl.publicKey();
        requireLength("A04 assertion Ed25519 public key", edPk, 32);
        requireLength("A04 assertion ML-DSA-65 public key", mlPk, 1952);

        byte[] edCose = OpenIdentityCbor.ed25519CoseKey(edPk);
        byte[] mlCose = OpenIdentityCbor.mlDsa65CoseKey(mlPk);
        var edMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID_B, edCose);
        var mlMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ML_DSA_METHOD_ID_B, mlCose);

        // Deliberately reverse input order. thresholdPolicy() must canonicalize.
        byte[] assertionPolicy = OpenIdentityCbor.thresholdPolicy(
                2, List.of(mlMethod, edMethod));

        byte[] operation = OpenIdentityCbor.setAssertionPolicyOperation(
                TestKeys.IDENTITY, 5, a03.stateHash(), assertionPolicy);

        byte[] authInput = OpenIdentityCbor.operationSigningInput(operation);
        byte[] controllerEdSig = controllerEd.sign(authInput);
        byte[] controllerMlSig = controllerMl.sign(authInput);
        if (!controllerEd.verify(authInput, controllerEdSig)
                || !controllerMl.verify(authInput, controllerMlSig)) {
            throw new IllegalStateException("A04 controller authorization failed");
        }

        var controllerEdProof = OpenIdentityCbor.authorizationProof(
                TestKeys.ED25519_METHOD_ID, controllerEdSig);
        var controllerMlProof = OpenIdentityCbor.authorizationProof(
                TestKeys.ML_DSA_METHOD_ID, controllerMlSig);

        byte[] edPopInput = OpenIdentityCbor.controllerProofSigningInput(
                operation, TestKeys.ED25519_METHOD_ID_B);
        byte[] mlPopInput = OpenIdentityCbor.controllerProofSigningInput(
                operation, TestKeys.ML_DSA_METHOD_ID_B);
        byte[] edPopSig = assertionEd.sign(edPopInput);
        byte[] mlPopSig = assertionMl.sign(mlPopInput);

        if (!assertionEd.verify(edPopInput, edPopSig)
                || !assertionMl.verify(mlPopInput, mlPopSig)) {
            throw new IllegalStateException("A04 assertion-key proof of possession failed");
        }

        var edPop = OpenIdentityCbor.controllerProof(
                TestKeys.ED25519_METHOD_ID_B, edPopSig);
        var mlPop = OpenIdentityCbor.controllerProof(
                TestKeys.ML_DSA_METHOD_ID_B, mlPopSig);

        // Reverse PoP input order as an additional canonical-order test.
        byte[] signed = OpenIdentityCbor.signedOperation(
                operation,
                List.of(controllerMlProof, controllerEdProof),
                List.of(mlPop, edPop));

        byte[] resultState = OpenIdentityCbor.activeIdentityStateV2(
                TestKeys.IDENTITY, 5, v02.controllerPolicy(), assertionPolicy);
        byte[] resultHash = StateHash.sha256Multihash(resultState);

        if (Arrays.equals(a03.stateHash(), resultHash))
            throw new IllegalStateException("A04 StateHash unexpectedly equals A03");

        requireLength("A04 controller Ed25519 signature", controllerEdSig, 64);
        requireLength("A04 controller ML-DSA-65 signature", controllerMlSig, 3309);
        requireLength("A04 assertion Ed25519 PoP signature", edPopSig, 64);
        requireLength("A04 assertion ML-DSA-65 PoP signature", mlPopSig, 3309);
        requireLength("A04 StateHash", resultHash, 34);

        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", "A04");
        v.put("description",
                "SET_ASSERTION_POLICY installs hybrid THRESHOLD 2-of-2 Ed25519 + ML-DSA-65 assertion authority");
        put(v, "identityHex", TestKeys.IDENTITY);
        v.put("sourceVector", "A03");
        v.put("previousIdentityStateVersion", 2);
        v.put("resultingIdentityStateVersion", 2);
        v.put("sequence", 5);
        put(v, "previousIdentityStateHex", a03.identityState());
        put(v, "previousStateHashHex", a03.stateHash());
        put(v, "controllerPolicyHex", v02.controllerPolicy());

        put(v, "assertionEd25519MethodIdHex", TestKeys.ED25519_METHOD_ID_B);
        put(v, "assertionMlDsa65MethodIdHex", TestKeys.ML_DSA_METHOD_ID_B);
        put(v, "assertionEd25519PublicKeyHex", edPk);
        put(v, "assertionMlDsa65PublicKeyHex", mlPk);
        put(v, "assertionEd25519CoseKeyHex", edCose);
        put(v, "assertionMlDsa65CoseKeyHex", mlCose);
        put(v, "assertionEd25519VerificationMethodHex", edMethod.encoded());
        put(v, "assertionMlDsa65VerificationMethodHex", mlMethod.encoded());
        put(v, "assertionPolicyHex", assertionPolicy);
        v.put("assertionPolicyType", "THRESHOLD");
        v.put("assertionThreshold", 2);
        v.put("assertionMethodCount", 2);
        v.put("inputMethodOrder", List.of("ML-DSA-65", "Ed25519"));
        v.put("inputPopOrder", List.of("ML-DSA-65", "Ed25519"));

        put(v, "operationBytesHex", operation);
        put(v, "authorizationSigningInputHex", authInput);
        put(v, "controllerEd25519AuthorizationSignatureHex", controllerEdSig);
        put(v, "controllerMlDsa65AuthorizationSignatureHex", controllerMlSig);
        put(v, "controllerEd25519AuthorizationProofHex", controllerEdProof.encoded());
        put(v, "controllerMlDsa65AuthorizationProofHex", controllerMlProof.encoded());

        put(v, "assertionEd25519PopSigningInputHex", edPopInput);
        put(v, "assertionMlDsa65PopSigningInputHex", mlPopInput);
        put(v, "assertionEd25519PopSignatureHex", edPopSig);
        put(v, "assertionMlDsa65PopSignatureHex", mlPopSig);
        put(v, "assertionEd25519ProofOfPossessionHex", edPop.encoded());
        put(v, "assertionMlDsa65ProofOfPossessionHex", mlPop.encoded());

        put(v, "signedOperationHex", signed);
        put(v, "resultingIdentityStateHex", resultState);
        put(v, "resultingStateHashHex", resultHash);

        v.put("authorizationProofCount", 2);
        v.put("assertionProofOfPossessionCount", 2);
        v.put("controllerPolicyPreserved", true);
        v.put("stateHashLength", resultHash.length);

        Map<String, Object> d = new LinkedHashMap<>();
        d.put("specification", "OpenIdentity Assertion Authority");
        d.put("version", "0.1");
        d.put("wireProtocolVersion", 1);
        d.put("sourceIdentityStateVersion", 2);
        d.put("resultingIdentityStateVersion", 2);
        d.put("vector", v);
        writeJson("assertion-a04-java.json", d);

        success("A03 StateHash used as previousStateHash");
        success("Current ControllerPolicy authorization verified");
        success("Ed25519 assertion proof-of-possession verified");
        success("ML-DSA-65 assertion proof-of-possession verified");
        success("THRESHOLD 2-of-2 AssertionPolicy canonically ordered");
        success("IdentityState remains v2");
        success("ControllerPolicy preserved");
        success("Resulting v2 IdentityState and StateHash generated");
        success("assertion-a04-java.json");
        blankLine();

        return new AssertionStateResult(assertionPolicy, resultState, resultHash);
    }


    /**
     * OI-003 invalid/security vectors AI01-AI10.
     * <p>
     * These vectors deliberately use raw encoders where the canonical
     * OpenIdentityCbor API correctly refuses to construct malformed objects.
     */
    private static void generateAssertionInvalidVectors(
            HybridCreateResult v02,
            AssertionStateResult a01,
            AssertionStateResult a02,
            AssertionStateResult a03) {
        section("ASSERTION INVALID", "AI01-AI10");

        var controllerEd = new Ed25519Support(TestKeys.ED25519_SEED);
        var controllerMl = new MlDsa65Support(TestKeys.ML_DSA_SEED);
        var assertionB = new Ed25519Support(TestKeys.ED25519_SEED_B);
        var assertionC = new Ed25519Support(TestKeys.ED25519_SEED_C);

        var methodB = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID_B,
                OpenIdentityCbor.ed25519CoseKey(assertionB.publicKey()));
        var methodC = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID_C,
                OpenIdentityCbor.ed25519CoseKey(assertionC.publicKey()));
        byte[] policyC = OpenIdentityCbor.singlePolicy(methodC);

        List<Map<String, Object>> vs = new ArrayList<>();

        // Common valid A01 -> proposed C replacement operation (sequence 3).
        byte[] replaceC = OpenIdentityCbor.setAssertionPolicyOperation(
                TestKeys.IDENTITY, 3, a01.stateHash(), policyC);
        byte[] replaceCAuthInput = OpenIdentityCbor.operationSigningInput(replaceC);
        var controllerEdProof = OpenIdentityCbor.authorizationProof(
                TestKeys.ED25519_METHOD_ID, controllerEd.sign(replaceCAuthInput));
        var controllerMlProof = OpenIdentityCbor.authorizationProof(
                TestKeys.ML_DSA_METHOD_ID, controllerMl.sign(replaceCAuthInput));
        byte[] cPopInput = OpenIdentityCbor.controllerProofSigningInput(
                replaceC, TestKeys.ED25519_METHOD_ID_C);
        var cPop = OpenIdentityCbor.controllerProof(
                TestKeys.ED25519_METHOD_ID_C, assertionC.sign(cPopInput));

        // AI01: assertion key B has a cryptographically valid signature, but B
        // is not a member of ControllerPolicy and therefore cannot authorize
        // SET_ASSERTION_POLICY.
        var bSelfAuth = OpenIdentityCbor.authorizationProof(
                TestKeys.ED25519_METHOD_ID_B,
                assertionB.sign(replaceCAuthInput));
        vs.add(assertionInvalidSigned(
                "AI01",
                "Assertion key self-authorizes AssertionPolicy replacement",
                "CONTROLLER_THRESHOLD_NOT_SATISFIED",
                "A01",
                a01.identityState(),
                a01.stateHash(),
                replaceC,
                rawSignedOperation(replaceC, List.of(bSelfAuth), List.of(cPop))));

        // AI02: valid controller authorization, but the newly proposed key C
        // supplies no proof of possession.
        vs.add(assertionInvalidSigned(
                "AI02",
                "New non-null AssertionPolicy is missing proposed-key proof of possession",
                "MISSING_PROOF_OF_POSSESSION",
                "A01",
                a01.identityState(),
                a01.stateHash(),
                replaceC,
                rawSignedOperation(
                        replaceC,
                        List.of(controllerEdProof, controllerMlProof),
                        List.of())));

        // AI03: key C signs the authorization-domain bytes rather than the
        // controller/proposed-key proof domain.
        var wrongDomainPop = OpenIdentityCbor.controllerProof(
                TestKeys.ED25519_METHOD_ID_C,
                assertionC.sign(replaceCAuthInput));
        vs.add(assertionInvalidSigned(
                "AI03",
                "Assertion-key proof of possession uses authorization signing domain",
                "INVALID_PROOF_OF_POSSESSION",
                "A01",
                a01.identityState(),
                a01.stateHash(),
                replaceC,
                rawSignedOperation(
                        replaceC,
                        List.of(controllerEdProof, controllerMlProof),
                        List.of(wrongDomainPop))));

        // AI04: key C signs a PoP input bound to method B, but the proof claims
        // method C. Signature bytes are therefore not valid for C's required
        // method-bound PoP input.
        byte[] wrongBoundInput = OpenIdentityCbor.controllerProofSigningInput(
                replaceC, TestKeys.ED25519_METHOD_ID_B);
        var wrongBoundPop = OpenIdentityCbor.controllerProof(
                TestKeys.ED25519_METHOD_ID_C,
                assertionC.sign(wrongBoundInput));
        vs.add(assertionInvalidSigned(
                "AI04",
                "Assertion-key proof of possession is bound to the wrong Verification Method ID",
                "INVALID_PROOF_OF_POSSESSION",
                "A01",
                a01.identityState(),
                a01.stateHash(),
                replaceC,
                rawSignedOperation(
                        replaceC,
                        List.of(controllerEdProof, controllerMlProof),
                        List.of(wrongBoundPop))));

        // AI05: previousStateHash does not identify the current A01 state.
        byte[] wrongHash = Arrays.copyOf(a01.stateHash(), a01.stateHash().length);
        wrongHash[wrongHash.length - 1] ^= 1;
        byte[] badHashOp = OpenIdentityCbor.setAssertionPolicyOperation(
                TestKeys.IDENTITY, 3, wrongHash, policyC);
        vs.add(assertionInvalidOperation(
                "AI05",
                "SET_ASSERTION_POLICY previousStateHash does not match current state",
                "INVALID_PREVIOUS_STATE_HASH",
                "A01",
                a01.identityState(),
                a01.stateHash(),
                badHashOp));

        // AI06: current A01 sequence is 2, so next must be 3, not 4.
        byte[] badSequenceOp = OpenIdentityCbor.setAssertionPolicyOperation(
                TestKeys.IDENTITY, 4, a01.stateHash(), policyC);
        vs.add(assertionInvalidOperation(
                "AI06",
                "SET_ASSERTION_POLICY sequence is not current sequence plus one",
                "INVALID_SEQUENCE",
                "A01",
                a01.identityState(),
                a01.stateHash(),
                badSequenceOp));

        // AI07: A01 retains V02's 2-of-2 ControllerPolicy, but only the
        // Ed25519 controller authorization proof is supplied.
        vs.add(assertionInvalidSigned(
                "AI07",
                "Controller threshold is not satisfied",
                "CONTROLLER_THRESHOLD_NOT_SATISFIED",
                "A01",
                a01.identityState(),
                a01.stateHash(),
                replaceC,
                rawSignedOperation(
                        replaceC,
                        List.of(controllerEdProof),
                        List.of(cPop))));

        // AI08: malformed threshold AssertionPolicy containing duplicate
        // Verification Method IDs. The canonical policy API correctly refuses
        // this, so construct the invalid bytes directly.
        byte[] duplicatePolicy = rawThresholdPolicy(
                2, List.of(methodC, methodC));
        byte[] duplicatePolicyOp = rawSetAssertionPolicyOperation(
                TestKeys.IDENTITY, 3, a01.stateHash(), duplicatePolicy);
        vs.add(assertionInvalidOperation(
                "AI08",
                "Proposed AssertionPolicy contains duplicate Verification Method IDs",
                "DUPLICATE_VERIFICATION_METHOD",
                "A01",
                a01.identityState(),
                a01.stateHash(),
                duplicatePolicyOp));

        // AI09: malformed threshold 2-of-1.
        byte[] invalidThresholdPolicy = rawThresholdPolicy(
                2, List.of(methodC));
        byte[] invalidThresholdOp = rawSetAssertionPolicyOperation(
                TestKeys.IDENTITY, 3, a01.stateHash(), invalidThresholdPolicy);
        vs.add(assertionInvalidOperation(
                "AI09",
                "AssertionPolicy threshold exceeds Verification Method count",
                "INVALID_ASSERTION_THRESHOLD",
                "A01",
                a01.identityState(),
                a01.stateHash(),
                invalidThresholdOp));

        // AI10: demonstrate the forbidden v2 -> v1 state downgrade. The
        // operation is a valid A02 -> removal operation; the supplied proposed
        // resulting state is intentionally encoded as v1.
        byte[] removeFromA02 = OpenIdentityCbor.setAssertionPolicyOperation(
                TestKeys.IDENTITY, 4, a02.stateHash(), null);
        byte[] removeAuthInput = OpenIdentityCbor.operationSigningInput(removeFromA02);
        var removeEdProof = OpenIdentityCbor.authorizationProof(
                TestKeys.ED25519_METHOD_ID, controllerEd.sign(removeAuthInput));
        var removeMlProof = OpenIdentityCbor.authorizationProof(
                TestKeys.ML_DSA_METHOD_ID, controllerMl.sign(removeAuthInput));
        byte[] validRemovalSigned = OpenIdentityCbor.signedOperation(
                removeFromA02, List.of(removeEdProof, removeMlProof));
        byte[] invalidDowngradedState = OpenIdentityCbor.activeIdentityState(
                TestKeys.IDENTITY, 4, v02.controllerPolicy());

        Map<String, Object> ai10 = assertionInvalidSigned(
                "AI10",
                "IdentityState v2 transition attempts to produce IdentityState v1",
                "STATE_VERSION_DOWNGRADE",
                "A02",
                a02.identityState(),
                a02.stateHash(),
                removeFromA02,
                validRemovalSigned);
        put(ai10, "invalidResultingIdentityStateHex", invalidDowngradedState);
        ai10.put("previousIdentityStateVersion", 2);
        ai10.put("invalidResultingIdentityStateVersion", 1);
        vs.add(ai10);

        List<String> actualIds = vs.stream()
                .map(v -> (String) v.get("id"))
                .toList();
        List<String> expectedIds = java.util.stream.IntStream.rangeClosed(1, 10)
                .mapToObj(i -> String.format("AI%02d", i))
                .toList();
        if (!actualIds.equals(expectedIds)) {
            throw new IllegalStateException(
                    "Unexpected assertion invalid vector IDs: " + actualIds);
        }

        Map<String, Object> d = new LinkedHashMap<>();
        d.put("specification", "OpenIdentity Assertion Authority");
        d.put("version", "0.1");
        d.put("type", "invalid-conformance-vectors");
        d.put("wireProtocolVersion", 1);
        d.put("vectors", vs);
        writeJson("assertion-invalid-java.json", d);

        success("AI01 assertion key self-authorization generated");
        success("AI02 missing assertion-key PoP generated");
        success("AI03 wrong PoP signing domain generated");
        success("AI04 wrong PoP method binding generated");
        success("AI05 incorrect previousStateHash generated");
        success("AI06 invalid sequence generated");
        success("AI07 insufficient ControllerPolicy authorization generated");
        success("AI08 duplicate assertion method ID generated");
        success("AI09 invalid assertion threshold generated");
        success("AI10 v2 -> v1 downgrade generated");
        success("AI01-AI10 generated");
        success("assertion-invalid-java.json");
        blankLine();
    }

    private static Map<String, Object> assertionInvalidOperation(
            String id,
            String description,
            String expectedError,
            String sourceVector,
            byte[] previousState,
            byte[] previousStateHash,
            byte[] operation) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", id);
        v.put("description", description);
        v.put("expectedError", expectedError);
        v.put("sourceVector", sourceVector);
        put(v, "previousIdentityStateHex", previousState);
        put(v, "previousStateHashHex", previousStateHash);
        put(v, "operationBytesHex", operation);
        return v;
    }

    private static Map<String, Object> assertionInvalidSigned(
            String id,
            String description,
            String expectedError,
            String sourceVector,
            byte[] previousState,
            byte[] previousStateHash,
            byte[] operation,
            byte[] signedOperation) {
        Map<String, Object> v = assertionInvalidOperation(
                id, description, expectedError, sourceVector,
                previousState, previousStateHash, operation);
        put(v, "signedOperationHex", signedOperation);
        return v;
    }

    /**
     * Raw SET_ASSERTION_POLICY encoder used only for invalid vectors whose
     * malformed AssertionPolicy cannot be produced through OpenIdentityCbor.
     */
    private static byte[] rawSetAssertionPolicyOperation(
            byte[] identity,
            long sequence,
            byte[] previousStateHash,
            byte[] assertionPolicy) {
        var payload = new DeterministicCborWriter();
        payload.writeMapHeader(1);
        payload.writeUnsigned(1);
        if (assertionPolicy == null) payload.writeNull();
        else payload.writeEncoded(assertionPolicy);

        var c = new DeterministicCborWriter();
        c.writeMapHeader(6);
        c.writeUnsigned(1);
        c.writeUnsigned(1);
        c.writeUnsigned(2);
        c.writeUnsigned(5);
        c.writeUnsigned(3);
        c.writeByteString(identity);
        c.writeUnsigned(4);
        c.writeUnsigned(sequence);
        c.writeUnsigned(5);
        c.writeByteString(previousStateHash);
        c.writeUnsigned(6);
        c.writeEncoded(payload.toByteArray());
        return c.toByteArray();
    }


    /**
     * Consolidates generated OI-003 assertion-authority vectors into the
     * normative v0.1 artifact and writes SHA-256 over the exact JSON bytes.
     */
    @SuppressWarnings("unchecked")
    private static void generateNormativeAssertionAuthorityFile() {
        section("NORMATIVE", "Consolidating OI-003 assertion-authority vectors");
        try {
            Path root = Path.of("..", "..").toAbsolutePath().normalize();
            Path gen = root.resolve("test-vectors").resolve("generated");
            Path tv = root.resolve("test-vectors");
            ObjectMapper mapper = new ObjectMapper();

            List<Map<String, Object>> valid = new ArrayList<>();
            for (String name : List.of(
                    "assertion-a01-java.json",
                    "assertion-a02-java.json",
                    "assertion-a03-java.json",
                    "assertion-a04-java.json")) {
                Map<String, Object> d = mapper.readValue(
                        gen.resolve(name).toFile(), Map.class);
                Object raw = d.get("vector");
                if (!(raw instanceof Map<?, ?>)) {
                    throw new IllegalStateException(
                            name + " missing vector object");
                }
                valid.add((Map<String, Object>) raw);
            }

            List<String> validIds = valid.stream()
                    .map(v -> (String) v.get("id"))
                    .toList();
            if (!validIds.equals(List.of("A01", "A02", "A03", "A04"))) {
                throw new IllegalStateException(
                        "Unexpected OI-003 valid vector IDs: " + validIds);
            }

            Map<String, Object> invalidDoc = mapper.readValue(
                    gen.resolve("assertion-invalid-java.json").toFile(),
                    Map.class);
            Object invalidRaw = invalidDoc.get("vectors");
            if (!(invalidRaw instanceof List<?>)) {
                throw new IllegalStateException(
                        "assertion-invalid-java.json missing vectors array");
            }
            List<Map<String, Object>> invalid =
                    (List<Map<String, Object>>) invalidRaw;

            List<String> expectedInvalid =
                    java.util.stream.IntStream.rangeClosed(1, 10)
                            .mapToObj(i -> String.format("AI%02d", i))
                            .toList();
            List<String> actualInvalid = invalid.stream()
                    .map(v -> (String) v.get("id"))
                    .toList();
            if (!actualInvalid.equals(expectedInvalid)) {
                throw new IllegalStateException(
                        "Unexpected OI-003 invalid vector IDs: " + actualInvalid);
            }

            Map<String, Object> normative = new LinkedHashMap<>();
            normative.put("specification", "OpenIdentity Assertion Authority");
            normative.put("version", "0.1");
            normative.put("wireProtocolVersion", 1);
            normative.put("identityStateVersions", List.of(1, 2));
            normative.put("validVectors", valid);
            normative.put("invalidVectors", invalid);

            ObjectMapper output = new ObjectMapper()
                    .enable(SerializationFeature.INDENT_OUTPUT);
            Path jsonFile = tv.resolve("assertion-authority-v0.1.json");
            output.writeValue(jsonFile.toFile(), normative);

            // Hash the exact bytes Jackson wrote to disk.
            byte[] jsonBytes = Files.readAllBytes(jsonFile);
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(jsonBytes);
            String sha256 = Hex.encode(digest);

            Path checksumFile =
                    tv.resolve("assertion-authority-v0.1.json.sha256");
            Files.writeString(
                    checksumFile,
                    sha256 + "  assertion-authority-v0.1.json\n");

            success("A01-A04 consolidated");
            success("AI01-AI10 consolidated");
            success("assertion-authority-v0.1.json");
            success("SHA-256 " + sha256);
            success("assertion-authority-v0.1.json.sha256");
            blankLine();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Unable to generate normative OI-003 vector file", e);
        }
    }


    /**
     * C01 -- first native OI-003 credential vector.
     * <p>
     * Uses A01 as the exact historical authorization state. A01 contains
     * SINGLE assertion authority for Ed25519 method B.
     */
    private static void generateC01(AssertionStateResult a01) {
        section("C01", "SINGLE Ed25519 credential issued against historical A01 state");

        byte[] credentialId = Hex.decode(
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
                        + "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
        byte[] subject = "alice@example.test".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String profile = "https://openidentity.foundation/test/credentials/basic/v1";
        long validFrom = 1787590800L;   // 2026-08-24T17:00:00Z
        long validUntil = 1819126800L;  // 2027-08-24T17:00:00Z

        Map<String, Object> claims = new LinkedHashMap<>();
        // Deliberately non-canonical insertion order; encoder must canonicalize.
        claims.put("role", "member");
        claims.put("name", "Alice Example");
        claims.put("active", true);

        byte[] credential = OpenIdentityCbor.openIdentityCredential(
                credentialId,
                TestKeys.IDENTITY,
                a01.stateHash(),
                validFrom,
                validUntil,
                profile,
                subject,
                claims);

        byte[] signingInput = OpenIdentityCbor.credentialSigningInput(credential);

        var assertionB = new Ed25519Support(TestKeys.ED25519_SEED_B);
        byte[] signature = assertionB.sign(signingInput);
        if (!assertionB.verify(signingInput, signature))
            throw new IllegalStateException("C01 Ed25519 credential signature failed");

        var proof = OpenIdentityCbor.credentialProof(
                TestKeys.ED25519_METHOD_ID_B, signature);
        byte[] secured = OpenIdentityCbor.securedCredential(
                credential, List.of(proof));

        requireLength("C01 credential ID", credentialId, 32);
        requireLength("C01 issuance StateHash", a01.stateHash(), 34);
        requireLength("C01 assertion method ID", TestKeys.ED25519_METHOD_ID_B, 16);
        requireLength("C01 Ed25519 signature", signature, 64);

        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", "C01");
        v.put("description",
                "SINGLE Ed25519 credential bound to historical A01 AssertionPolicy");
        v.put("sourceAssertionVector", "A01");
        v.put("credentialVersion", 1);
        put(v, "credentialIdHex", credentialId);
        put(v, "issuerIdentityHex", TestKeys.IDENTITY);
        put(v, "issuanceStateHashHex", a01.stateHash());
        put(v, "historicalIdentityStateHex", a01.identityState());
        v.put("validFrom", validFrom);
        v.put("validUntil", validUntil);
        v.put("credentialProfile", profile);
        put(v, "credentialSubjectHex", subject);
        v.put("claims", claims);
        put(v, "assertionMethodIdHex", TestKeys.ED25519_METHOD_ID_B);
        put(v, "credentialBytesHex", credential);
        put(v, "credentialSigningInputHex", signingInput);
        put(v, "credentialSignatureHex", signature);
        put(v, "credentialProofHex", proof.encoded());
        put(v, "securedCredentialHex", secured);
        v.put("proofCount", 1);
        v.put("assertionPolicyType", "SINGLE");
        v.put("assertionThreshold", 1);
        v.put("signatureAlgorithm", "Ed25519");
        v.put("signatureLength", signature.length);

        Map<String, Object> d = new LinkedHashMap<>();
        d.put("specification", "OpenIdentity Credential");
        d.put("version", "0.1");
        d.put("credentialWireVersion", 1);
        d.put("vector", v);
        writeJson("credential-c01-java.json", d);

        success("A01 historical StateHash bound into CredentialBytes");
        success("SINGLE assertion method B selected from A01");
        success("Credential claims canonically encoded");
        success("Credential signing input generated");
        success("Ed25519 credential signature verified");
        success("SecuredCredential generated");
        success("credential-c01-java.json");
        blankLine();
    }


    /**
     * C02 -- hybrid THRESHOLD 2-of-2 native OI-003 credential.
     * <p>
     * Uses A04 as the exact historical authorization state. A04 contains
     * Ed25519 B + ML-DSA-65 B assertion authority with threshold 2-of-2.
     */
    private static void generateC02(AssertionStateResult a04) {
        section("C02", "THRESHOLD 2-of-2 Ed25519 + ML-DSA-65 credential issued against historical A04 state");

        byte[] credentialId = Hex.decode(
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                        + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf");
        byte[] subject = "alice@example.test".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String profile = "https://openidentity.foundation/test/credentials/basic/v1";
        long validFrom = 1787590800L;   // 2026-08-24T17:00:00Z
        long validUntil = 1819126800L;  // 2027-08-24T17:00:00Z

        Map<String, Object> claims = new LinkedHashMap<>();
        // Deliberately non-canonical insertion order; encoder must canonicalize.
        claims.put("role", "hybrid-member");
        claims.put("name", "Alice Example");
        claims.put("active", true);

        byte[] credential = OpenIdentityCbor.openIdentityCredential(
                credentialId,
                TestKeys.IDENTITY,
                a04.stateHash(),
                validFrom,
                validUntil,
                profile,
                subject,
                claims);

        byte[] signingInput = OpenIdentityCbor.credentialSigningInput(credential);

        var assertionEd = new Ed25519Support(TestKeys.ED25519_SEED_B);
        var assertionMl = new MlDsa65Support(TestKeys.ML_DSA_SEED_B);

        byte[] edSignature = assertionEd.sign(signingInput);
        byte[] mlSignature = assertionMl.sign(signingInput);

        if (!assertionEd.verify(signingInput, edSignature))
            throw new IllegalStateException("C02 Ed25519 credential signature failed");
        if (!assertionMl.verify(signingInput, mlSignature))
            throw new IllegalStateException("C02 ML-DSA-65 credential signature failed");

        var edProof = OpenIdentityCbor.credentialProof(
                TestKeys.ED25519_METHOD_ID_B, edSignature);
        var mlProof = OpenIdentityCbor.credentialProof(
                TestKeys.ML_DSA_METHOD_ID_B, mlSignature);

        // Deliberately reversed input order. securedCredential() MUST
        // canonicalize by unsigned Verification Method ID.
        byte[] secured = OpenIdentityCbor.securedCredential(
                credential, List.of(mlProof, edProof));

        requireLength("C02 credential ID", credentialId, 32);
        requireLength("C02 issuance StateHash", a04.stateHash(), 34);
        requireLength("C02 Ed25519 method ID", TestKeys.ED25519_METHOD_ID_B, 16);
        requireLength("C02 ML-DSA-65 method ID", TestKeys.ML_DSA_METHOD_ID_B, 16);
        requireLength("C02 Ed25519 signature", edSignature, 64);
        requireLength("C02 ML-DSA-65 signature", mlSignature, 3309);

        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", "C02");
        v.put("description",
                "THRESHOLD 2-of-2 Ed25519 + ML-DSA-65 credential bound to historical A04 AssertionPolicy");
        v.put("sourceAssertionVector", "A04");
        v.put("credentialVersion", 1);
        put(v, "credentialIdHex", credentialId);
        put(v, "issuerIdentityHex", TestKeys.IDENTITY);
        put(v, "issuanceStateHashHex", a04.stateHash());
        put(v, "historicalIdentityStateHex", a04.identityState());
        v.put("validFrom", validFrom);
        v.put("validUntil", validUntil);
        v.put("credentialProfile", profile);
        put(v, "credentialSubjectHex", subject);
        v.put("claims", claims);

        put(v, "ed25519MethodIdHex", TestKeys.ED25519_METHOD_ID_B);
        put(v, "mlDsa65MethodIdHex", TestKeys.ML_DSA_METHOD_ID_B);
        put(v, "credentialBytesHex", credential);
        put(v, "credentialSigningInputHex", signingInput);
        put(v, "ed25519SignatureHex", edSignature);
        put(v, "mlDsa65SignatureHex", mlSignature);
        put(v, "ed25519ProofHex", edProof.encoded());
        put(v, "mlDsa65ProofHex", mlProof.encoded());
        put(v, "securedCredentialHex", secured);

        v.put("inputProofOrder", List.of("ML-DSA-65", "Ed25519"));
        v.put("canonicalProofOrder", List.of("Ed25519", "ML-DSA-65"));
        v.put("proofCount", 2);
        v.put("assertionPolicyType", "THRESHOLD");
        v.put("assertionThreshold", 2);
        v.put("assertionMethodCount", 2);
        v.put("ed25519SignatureAlgorithm", "Ed25519");
        v.put("mlDsa65SignatureAlgorithm", "ML-DSA-65");
        v.put("ed25519SignatureLength", edSignature.length);
        v.put("mlDsa65SignatureLength", mlSignature.length);

        Map<String, Object> d = new LinkedHashMap<>();
        d.put("specification", "OpenIdentity Credential");
        d.put("version", "0.1");
        d.put("credentialWireVersion", 1);
        d.put("vector", v);
        writeJson("credential-c02-java.json", d);

        success("A04 historical StateHash bound into CredentialBytes");
        success("THRESHOLD 2-of-2 AssertionPolicy selected from A04");
        success("Credential claims canonically encoded");
        success("Credential signing input generated");
        success("Ed25519 credential signature verified");
        success("ML-DSA-65 credential signature verified");
        success("Reversed proof input canonically ordered");
        success("2-of-2 assertion threshold satisfied");
        success("SecuredCredential generated");
        success("credential-c02-java.json");
        blankLine();
    }


    /**
     * OI-003 credential invalid/security vectors CI01-CI10.
     */
    private static void generateCredentialInvalidVectors(
            AssertionStateResult a01,
            AssertionStateResult a03,
            AssertionStateResult a04) {
        section("CREDENTIAL INVALID", "CI01-CI10");

        String profile = "https://openidentity.foundation/test/credentials/basic/v1";
        byte[] subject = "alice@example.test".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        long validFrom = 1787590800L;
        long validUntil = 1819126800L;

        var edB = new Ed25519Support(TestKeys.ED25519_SEED_B);
        var mlB = new MlDsa65Support(TestKeys.ML_DSA_SEED_B);
        var edC = new Ed25519Support(TestKeys.ED25519_SEED_C);
        List<Map<String, Object>> vectors = new ArrayList<>();

        byte[] hybridId = Hex.decode(
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                        + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf");
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("role", "hybrid-member");
        claims.put("name", "Alice Example");
        claims.put("active", true);

        byte[] credential = OpenIdentityCbor.openIdentityCredential(
                hybridId, TestKeys.IDENTITY, a04.stateHash(), validFrom,
                validUntil, profile, subject, claims);
        byte[] signing = OpenIdentityCbor.credentialSigningInput(credential);
        byte[] edSig = edB.sign(signing);
        byte[] mlSig = mlB.sign(signing);
        var edProof = OpenIdentityCbor.credentialProof(TestKeys.ED25519_METHOD_ID_B, edSig);
        var mlProof = OpenIdentityCbor.credentialProof(TestKeys.ML_DSA_METHOD_ID_B, mlSig);

        // CI01 -- insufficient 2-of-2 threshold.
        Map<String, Object> v = invalidCredentialBase(
                "CI01", "THRESHOLD 2-of-2 credential supplies only Ed25519 proof",
                "ASSERTION_THRESHOLD_NOT_SATISFIED", a04, credential);
        put(v, "credentialSigningInputHex", signing);
        put(v, "securedCredentialHex",
                OpenIdentityCbor.securedCredential(credential, List.of(edProof)));
        vectors.add(v);

        // CI02 -- duplicate method IDs. Raw encoder bypasses the correct helper rejection.
        v = invalidCredentialBase(
                "CI02", "Credential contains duplicate Ed25519 proof method IDs",
                "DUPLICATE_CREDENTIAL_PROOF", a04, credential);
        put(v, "duplicateMethodIdHex", TestKeys.ED25519_METHOD_ID_B);
        put(v, "securedCredentialHex",
                rawSecuredCredential(credential,
                        List.of(edProof.encoded(), edProof.encoded())));
        vectors.add(v);

        // CI03 -- extra valid signature from method C, absent from A04.
        byte[] cSig = edC.sign(signing);
        var cProof = OpenIdentityCbor.credentialProof(TestKeys.ED25519_METHOD_ID_C, cSig);
        v = invalidCredentialBase(
                "CI03", "Additional proof uses method absent from historical A04 AssertionPolicy",
                "UNAUTHORIZED_CREDENTIAL_PROOF", a04, credential);
        put(v, "unauthorizedMethodIdHex", TestKeys.ED25519_METHOD_ID_C);
        put(v, "unauthorizedSignatureHex", cSig);
        put(v, "securedCredentialHex",
                rawSecuredCredential(credential,
                        canonicalRawProofs(List.of(edProof, mlProof, cProof))));
        vectors.add(v);

        // CI04 -- corrupt authorized Ed25519 signature.
        byte[] badEd = edSig.clone();
        badEd[0] ^= 1;
        var badEdProof = OpenIdentityCbor.credentialProof(TestKeys.ED25519_METHOD_ID_B, badEd);
        v = invalidCredentialBase(
                "CI04", "Authorized Ed25519 proof contains corrupted signature",
                "INVALID_CREDENTIAL_SIGNATURE", a04, credential);
        put(v, "invalidSignatureHex", badEd);
        put(v, "securedCredentialHex",
                OpenIdentityCbor.securedCredential(credential, List.of(badEdProof, mlProof)));
        vectors.add(v);

        // CI05 -- corrupt authorized ML-DSA-65 signature.
        byte[] badMl = mlSig.clone();
        badMl[0] ^= 1;
        var badMlProof = OpenIdentityCbor.credentialProof(TestKeys.ML_DSA_METHOD_ID_B, badMl);
        v = invalidCredentialBase(
                "CI05", "Authorized ML-DSA-65 proof contains corrupted signature",
                "INVALID_CREDENTIAL_SIGNATURE", a04, credential);
        put(v, "invalidSignatureHex", badMl);
        put(v, "securedCredentialHex",
                OpenIdentityCbor.securedCredential(credential, List.of(edProof, badMlProof)));
        vectors.add(v);

        // CI06 -- credential commits to wrong StateHash while supplied historical state is A04.
        byte[] wrongHash = a04.stateHash().clone();
        wrongHash[wrongHash.length - 1] ^= 1;
        byte[] wrongHashCredential = OpenIdentityCbor.openIdentityCredential(
                Hex.decode("d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"),
                TestKeys.IDENTITY, wrongHash, validFrom, validUntil, profile, subject, claims);
        byte[] wrongHashSigning = OpenIdentityCbor.credentialSigningInput(wrongHashCredential);
        var whEd = OpenIdentityCbor.credentialProof(
                TestKeys.ED25519_METHOD_ID_B, edB.sign(wrongHashSigning));
        var whMl = OpenIdentityCbor.credentialProof(
                TestKeys.ML_DSA_METHOD_ID_B, mlB.sign(wrongHashSigning));
        v = invalidCredentialBase(
                "CI06", "Credential issuanceStateHash does not match resolved historical state",
                "INVALID_ISSUANCE_STATE_HASH", a04, wrongHashCredential);
        put(v, "authoritativeStateHashHex", a04.stateHash());
        put(v, "credentialIssuanceStateHashHex", wrongHash);
        put(v, "securedCredentialHex",
                OpenIdentityCbor.securedCredential(wrongHashCredential, List.of(whEd, whMl)));
        vectors.add(v);

        // CI07 -- both signatures are valid only over a wrong domain.
        byte[] wrongDomain = wrongCredentialSigningInput(credential);
        var wdEd = OpenIdentityCbor.credentialProof(
                TestKeys.ED25519_METHOD_ID_B, edB.sign(wrongDomain));
        var wdMl = OpenIdentityCbor.credentialProof(
                TestKeys.ML_DSA_METHOD_ID_B, mlB.sign(wrongDomain));
        v = invalidCredentialBase(
                "CI07", "Credential signatures use wrong signing domain",
                "INVALID_CREDENTIAL_SIGNATURE", a04, credential);
        put(v, "requiredSigningInputHex", signing);
        put(v, "wrongSigningInputHex", wrongDomain);
        put(v, "securedCredentialHex",
                OpenIdentityCbor.securedCredential(credential, List.of(wdEd, wdMl)));
        vectors.add(v);

        // CI08 -- valid B signature rebound to unauthorized method C.
        var rebound = OpenIdentityCbor.credentialProof(TestKeys.ED25519_METHOD_ID_C, edSig);
        v = invalidCredentialBase(
                "CI08", "Valid Ed25519 B signature is rebound to unauthorized method C",
                "UNAUTHORIZED_CREDENTIAL_PROOF", a04, credential);
        put(v, "originalAuthorizedMethodIdHex", TestKeys.ED25519_METHOD_ID_B);
        put(v, "reboundUnauthorizedMethodIdHex", TestKeys.ED25519_METHOD_ID_C);
        put(v, "securedCredentialHex",
                rawSecuredCredential(credential,
                        canonicalRawProofs(List.of(rebound, mlProof))));
        vectors.add(v);

        // CI09 -- C01 claims changed after signature creation.
        byte[] c01Id = Hex.decode(
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
                        + "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
        Map<String, Object> originalClaims = new LinkedHashMap<>();
        originalClaims.put("role", "member");
        originalClaims.put("name", "Alice Example");
        originalClaims.put("active", true);
        byte[] original = OpenIdentityCbor.openIdentityCredential(
                c01Id, TestKeys.IDENTITY, a01.stateHash(), validFrom, validUntil,
                profile, subject, originalClaims);
        byte[] originalSig = edB.sign(OpenIdentityCbor.credentialSigningInput(original));
        Map<String, Object> modifiedClaims = new LinkedHashMap<>(originalClaims);
        modifiedClaims.put("role", "administrator");
        byte[] modified = OpenIdentityCbor.openIdentityCredential(
                c01Id, TestKeys.IDENTITY, a01.stateHash(), validFrom, validUntil,
                profile, subject, modifiedClaims);
        v = invalidCredentialBase(
                "CI09", "Credential claims modified after signing",
                "INVALID_CREDENTIAL_SIGNATURE", a01, modified);
        put(v, "originalCredentialBytesHex", original);
        put(v, "originalSignatureHex", originalSig);
        put(v, "securedCredentialHex",
                OpenIdentityCbor.securedCredential(modified, List.of(
                        OpenIdentityCbor.credentialProof(TestKeys.ED25519_METHOD_ID_B, originalSig))));
        vectors.add(v);

        // CI10 -- A03 StateHash is correct, but A03 has no AssertionPolicy.
        byte[] noAuthCredential = OpenIdentityCbor.openIdentityCredential(
                Hex.decode("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
                TestKeys.IDENTITY, a03.stateHash(), validFrom, validUntil,
                profile, subject, claims);
        byte[] noAuthSigning = OpenIdentityCbor.credentialSigningInput(noAuthCredential);
        v = invalidCredentialBase(
                "CI10", "Credential binds to valid historical A03 state with no AssertionPolicy",
                "NO_ASSERTION_AUTHORITY", a03, noAuthCredential);
        put(v, "credentialSigningInputHex", noAuthSigning);
        put(v, "securedCredentialHex",
                OpenIdentityCbor.securedCredential(noAuthCredential, List.of(
                        OpenIdentityCbor.credentialProof(
                                TestKeys.ED25519_METHOD_ID_B, edB.sign(noAuthSigning)))));
        vectors.add(v);

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("specification", "OpenIdentity Credential");
        doc.put("version", "0.1");
        doc.put("type", "invalid-conformance-vectors");
        doc.put("credentialWireVersion", 1);
        doc.put("vectors", vectors);
        writeJson("credential-invalid-java.json", doc);

        for (int i = 1; i <= 10; i++)
            success(String.format("CI%02d generated", i));
        success("CI01-CI10 generated");
        success("credential-invalid-java.json");
        blankLine();
    }

    private static Map<String, Object> invalidCredentialBase(
            String id, String description, String expectedError,
            AssertionStateResult state, byte[] credential) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", id);
        v.put("description", description);
        v.put("expectedError", expectedError);
        put(v, "historicalIdentityStateHex", state.identityState());
        put(v, "issuanceStateHashHex", state.stateHash());
        put(v, "credentialBytesHex", credential);
        return v;
    }

    private static byte[] rawSecuredCredential(byte[] credential, List<byte[]> encodedProofs) {
        var c = new DeterministicCborWriter();
        c.writeMapHeader(2);
        c.writeUnsigned(1);
        c.writeEncoded(credential);
        c.writeUnsigned(2);
        c.writeArrayHeader(encodedProofs.size());
        for (byte[] p : encodedProofs) c.writeEncoded(p);
        return c.toByteArray();
    }

    private static List<byte[]> canonicalRawProofs(List<OpenIdentityCbor.EncodedProof> proofs) {
        List<OpenIdentityCbor.EncodedProof> sorted = new ArrayList<>(proofs);
        sorted.sort((a, b) -> {
            byte[] x = a.verificationMethodId(), y = b.verificationMethodId();
            for (int i = 0; i < Math.min(x.length, y.length); i++) {
                int cmp = Integer.compare(Byte.toUnsignedInt(x[i]), Byte.toUnsignedInt(y[i]));
                if (cmp != 0) return cmp;
            }
            return Integer.compare(x.length, y.length);
        });
        List<byte[]> out = new ArrayList<>();
        for (var p : sorted) out.add(p.encoded());
        return out;
    }

    private static byte[] wrongCredentialSigningInput(byte[] credentialBytes) {
        var c = new DeterministicCborWriter();
        c.writeArrayHeader(3);
        c.writeTextString("OpenIdentity Credential WRONG");
        c.writeUnsigned(1);
        c.writeByteString(credentialBytes);
        return c.toByteArray();
    }


    /**
     * Consolidates generated OI-003 credential vectors into the normative
     * credential-v0.1.json artifact and writes SHA-256 over the exact JSON
     * bytes written to disk.
     */
    @SuppressWarnings("unchecked")
    private static void generateNormativeCredentialFile() {
        section("NORMATIVE", "Consolidating OI-003 credential vectors");
        try {
            Path root = Path.of("..", "..").toAbsolutePath().normalize();
            Path gen = root.resolve("test-vectors").resolve("generated");
            Path tv = root.resolve("test-vectors");
            ObjectMapper mapper = new ObjectMapper();

            List<Map<String, Object>> valid = new ArrayList<>();
            for (String name : List.of(
                    "credential-c01-java.json",
                    "credential-c02-java.json")) {
                Map<String, Object> d = mapper.readValue(
                        gen.resolve(name).toFile(), Map.class);

                if (!"OpenIdentity Credential".equals(d.get("specification"))
                        || !"0.1".equals(d.get("version"))
                        || !Integer.valueOf(1).equals(d.get("credentialWireVersion"))) {
                    throw new IllegalStateException(
                            name + " has unexpected credential suite metadata");
                }

                Object raw = d.get("vector");
                if (!(raw instanceof Map<?, ?>)) {
                    throw new IllegalStateException(
                            name + " missing vector object");
                }
                valid.add((Map<String, Object>) raw);
            }

            List<String> validIds = valid.stream()
                    .map(v -> (String) v.get("id"))
                    .toList();
            if (!validIds.equals(List.of("C01", "C02"))) {
                throw new IllegalStateException(
                        "Unexpected OI-003 credential valid vector IDs: "
                                + validIds);
            }

            Map<String, Object> invalidDoc = mapper.readValue(
                    gen.resolve("credential-invalid-java.json").toFile(),
                    Map.class);

            if (!"OpenIdentity Credential".equals(invalidDoc.get("specification"))
                    || !"0.1".equals(invalidDoc.get("version"))
                    || !"invalid-conformance-vectors".equals(invalidDoc.get("type"))
                    || !Integer.valueOf(1).equals(
                    invalidDoc.get("credentialWireVersion"))) {
                throw new IllegalStateException(
                        "credential-invalid-java.json has unexpected suite metadata");
            }

            Object invalidRaw = invalidDoc.get("vectors");
            if (!(invalidRaw instanceof List<?>)) {
                throw new IllegalStateException(
                        "credential-invalid-java.json missing vectors array");
            }
            List<Map<String, Object>> invalid =
                    (List<Map<String, Object>>) invalidRaw;

            List<String> expectedInvalid =
                    java.util.stream.IntStream.rangeClosed(1, 10)
                            .mapToObj(i -> String.format("CI%02d", i))
                            .toList();
            List<String> actualInvalid = invalid.stream()
                    .map(v -> (String) v.get("id"))
                    .toList();
            if (!actualInvalid.equals(expectedInvalid)) {
                throw new IllegalStateException(
                        "Unexpected OI-003 credential invalid vector IDs: "
                                + actualInvalid);
            }

            Map<String, Object> normative = new LinkedHashMap<>();
            normative.put("specification", "OpenIdentity Credential");
            normative.put("version", "0.1");
            normative.put("credentialWireVersion", 1);
            normative.put("validVectors", valid);
            normative.put("invalidVectors", invalid);

            ObjectMapper output = new ObjectMapper()
                    .enable(SerializationFeature.INDENT_OUTPUT);
            Path jsonFile = tv.resolve("credential-v0.1.json");
            output.writeValue(jsonFile.toFile(), normative);

            // Hash the exact bytes Jackson wrote to disk.
            byte[] jsonBytes = Files.readAllBytes(jsonFile);
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(jsonBytes);
            String sha256 = Hex.encode(digest);

            Path checksumFile = tv.resolve("credential-v0.1.json.sha256");
            Files.writeString(
                    checksumFile,
                    sha256 + "  credential-v0.1.json\n");

            success("C01-C02 consolidated");
            success("CI01-CI10 consolidated");
            success("credential-v0.1.json");
            success("SHA-256 " + sha256);
            success("credential-v0.1.json.sha256");
            blankLine();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Unable to generate normative OI-003 credential vector file",
                    e);
        }
    }


    /**
     * WP01/WP02 -- deterministic W3C VC projections of frozen C01/C02.
     * <p>
     * Projection source of truth is the generated native credential vector.
     * No W3C Data Integrity proof is created; native security is preserved
     * in openIdentitySecuredCredential.
     */
    @SuppressWarnings("unchecked")
    private static void generateW3cCredentialProjectionVectors() {
        section("W3C CREDENTIAL PROJECTION", "WP01-WP02");
        try {
            Path root = Path.of("..", "..").toAbsolutePath().normalize();
            Path gen = root.resolve("test-vectors").resolve("generated");
            ObjectMapper mapper = new ObjectMapper();

            generateW3cCredentialProjection(
                    mapper, gen, "WP01", "C01",
                    "credential-c01-java.json", "member");
            generateW3cCredentialProjection(
                    mapper, gen, "WP02", "C02",
                    "credential-c02-java.json", "hybrid-member");

            success("WP01-WP02 generated");
            blankLine();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Unable to generate W3C credential projection vectors", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static void generateW3cCredentialProjection(
            ObjectMapper mapper,
            Path gen,
            String projectionId,
            String sourceId,
            String sourceFile,
            String expectedRole) throws Exception {

        Map<String, Object> sourceDoc =
                mapper.readValue(gen.resolve(sourceFile).toFile(), Map.class);
        Map<String, Object> v =
                (Map<String, Object>) sourceDoc.get("vector");

        if (!sourceId.equals(v.get("id")))
            throw new IllegalStateException(
                    projectionId + " unexpected source vector ID");

        String profile =
                "https://openidentity.foundation/test/credentials/basic/v1";
        if (!profile.equals(v.get("credentialProfile")))
            throw new IllegalStateException(
                    projectionId + " source profile is not Basic v1");

        byte[] credentialId = Hex.decode((String) v.get("credentialIdHex"));
        byte[] issuer = Hex.decode((String) v.get("issuerIdentityHex"));
        byte[] stateHash = Hex.decode((String) v.get("issuanceStateHashHex"));
        byte[] subject = Hex.decode((String) v.get("credentialSubjectHex"));
        byte[] secured = Hex.decode((String) v.get("securedCredentialHex"));

        String subjectText =
                new String(subject, java.nio.charset.StandardCharsets.UTF_8);
        if (!"alice@example.test".equals(subjectText))
            throw new IllegalStateException(
                    projectionId + " unexpected Basic v1 subject");

        Map<String, Object> claims =
                (Map<String, Object>) v.get("claims");
        if (claims.size() != 3
                || !"Alice Example".equals(claims.get("name"))
                || !expectedRole.equals(claims.get("role"))
                || !Boolean.TRUE.equals(claims.get("active"))) {
            throw new IllegalStateException(
                    projectionId + " source claims do not satisfy Basic v1");
        }

        String credentialUri =
                "urn:openidentity:credential:" + multibaseBase64Url(credentialId);
        String issuerDid = didOpen(issuer);
        String subjectUri =
                "urn:openidentity:test-subject:" + multibaseBase64Url(subject);
        String stateHashMb = multibaseBase58Btc(stateHash);
        String securedMb = multibaseBase64Url(secured);

        String validFrom = epochSecondsUtc(
                ((Number) v.get("validFrom")).longValue());
        String validUntil = epochSecondsUtc(
                ((Number) v.get("validUntil")).longValue());

        List<String> contexts = List.of(
                "https://www.w3.org/ns/credentials/v2",
                "https://openidentity.foundation/ns/v2",
                "https://openidentity.foundation/test/credentials/basic/v1/context");
        List<String> types = List.of(
                "VerifiableCredential",
                "OpenIdentityCredential",
                "OpenIdentityBasicCredential");

        Map<String, Object> projectedSubject = new LinkedHashMap<>();
        projectedSubject.put("id", subjectUri);
        projectedSubject.put("name", claims.get("name"));
        projectedSubject.put("role", claims.get("role"));
        projectedSubject.put("active", claims.get("active"));

        Map<String, Object> projection = new LinkedHashMap<>();
        projection.put("@context", contexts);
        projection.put("id", credentialUri);
        projection.put("type", types);
        projection.put("issuer", issuerDid);
        projection.put("validFrom", validFrom);
        projection.put("validUntil", validUntil);
        projection.put("credentialSubject", projectedSubject);
        projection.put("openIdentityCredentialProfile", profile);
        projection.put("openIdentityIssuanceStateHash", stateHashMb);
        projection.put("openIdentitySecuredCredential", securedMb);

        Map<String, Object> outVector = new LinkedHashMap<>();
        outVector.put("id", projectionId);
        outVector.put("sourceCredentialVector", sourceId);
        outVector.put("projectionVersion", 1);
        outVector.put("credentialIdUri", credentialUri);
        outVector.put("issuerDid", issuerDid);
        outVector.put("contexts", contexts);
        outVector.put("types", types);
        outVector.put("validFrom", validFrom);
        outVector.put("validUntil", validUntil);
        outVector.put("credentialProfile", profile);
        outVector.put("issuanceStateHashMultibase", stateHashMb);
        outVector.put("securedCredentialMultibase", securedMb);
        outVector.put("credentialSubject", projectedSubject);
        outVector.put("w3cCredential", projection);
        outVector.put("containsW3cProof", false);

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("specification", "OpenIdentity W3C Credential Projection");
        doc.put("version", "0.1");
        doc.put("vector", outVector);

        String file = "w3c-credential-" + projectionId.toLowerCase()
                + "-java.json";
        mapper.writerWithDefaultPrettyPrinter()
                .writeValue(gen.resolve(file).toFile(), doc);

        success(sourceId + " native credential projected deterministically");
        success("credential ID URI generated");
        success("issuer DID generated");
        success("Basic v1 subject URN generated");
        success("issuance StateHash Multibase generated");
        success("native SecuredCredential Multibase preserved");
        success("W3C proof omitted; native OI-003 proof remains authoritative");
        success(file);
    }

    private static String epochSecondsUtc(long seconds) {
        return java.time.Instant.ofEpochSecond(seconds).toString();
    }

    private static String multibaseBase64Url(byte[] bytes) {
        return "u" + java.util.Base64.getUrlEncoder()
                .withoutPadding().encodeToString(bytes);
    }

    private static String didOpen(byte[] identity) {
        return "did:open:" + multibaseBase58Btc(identity);
    }

    private static String multibaseBase58Btc(byte[] bytes) {
        return "z" + base58Btc(bytes);
    }

    private static String base58Btc(byte[] input) {
        final char[] alphabet =
                "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
                        .toCharArray();

        if (input.length == 0) return "";

        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) zeros++;

        byte[] work = input.clone();
        char[] encoded = new char[input.length * 2];
        int outputStart = encoded.length;

        int inputStart = zeros;
        while (inputStart < work.length) {
            int remainder = 0;
            for (int i = inputStart; i < work.length; i++) {
                int digit = Byte.toUnsignedInt(work[i]);
                int temp = remainder * 256 + digit;
                work[i] = (byte) (temp / 58);
                remainder = temp % 58;
            }
            encoded[--outputStart] = alphabet[remainder];
            while (inputStart < work.length && work[inputStart] == 0)
                inputStart++;
        }

        while (outputStart < encoded.length
                && encoded[outputStart] == alphabet[0])
            outputStart++;

        while (zeros-- > 0)
            encoded[--outputStart] = alphabet[0];

        return new String(encoded, outputStart, encoded.length - outputStart);
    }


    /**
     * WPI01-WPI10 -- invalid/security vectors for W3C credential projection.
     * <p>
     * These mutate only the projection layer unless a case explicitly tests
     * native secured-credential corruption or historical-state substitution.
     */
    @SuppressWarnings("unchecked")
    private static void generateW3cCredentialProjectionInvalidVectors() {
        section("W3C CREDENTIAL PROJECTION INVALID", "WPI01-WPI10");
        try {
            Path root = Path.of("..", "..").toAbsolutePath().normalize();
            Path gen = root.resolve("test-vectors").resolve("generated");
            ObjectMapper mapper = new ObjectMapper();

            Map<String, Object> wp01Doc = mapper.readValue(
                    gen.resolve("w3c-credential-wp01-java.json").toFile(), Map.class);
            Map<String, Object> wp02Doc = mapper.readValue(
                    gen.resolve("w3c-credential-wp02-java.json").toFile(), Map.class);
            Map<String, Object> c01Doc = mapper.readValue(
                    gen.resolve("credential-c01-java.json").toFile(), Map.class);
            Map<String, Object> c02Doc = mapper.readValue(
                    gen.resolve("credential-c02-java.json").toFile(), Map.class);

            Map<String, Object> wp01 = (Map<String, Object>) wp01Doc.get("vector");
            Map<String, Object> wp02 = (Map<String, Object>) wp02Doc.get("vector");
            Map<String, Object> c01 = (Map<String, Object>) c01Doc.get("vector");
            Map<String, Object> c02 = (Map<String, Object>) c02Doc.get("vector");

            List<Map<String, Object>> vectors = new ArrayList<>();

            // WPI01 -- projected issuer differs from signed native issuer.
            Map<String, Object> p = deepCopyMap(mapper,
                    (Map<String, Object>) wp01.get("w3cCredential"));
            p.put("issuer", "did:open:z11111111111111111111111111111111");
            vectors.add(wpi("WPI01", "WP01",
                    "Projected issuer differs from signed native issuer",
                    "INVALID_PROJECTED_ISSUER", p));

            // WPI02 -- projected credential ID differs.
            p = deepCopyMap(mapper,
                    (Map<String, Object>) wp01.get("w3cCredential"));
            p.put("id", "urn:openidentity:credential:uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
            vectors.add(wpi("WPI02", "WP01",
                    "Projected credential ID differs from native credentialId",
                    "INVALID_PROJECTED_CREDENTIAL_ID", p));

            // WPI03 -- projected validFrom differs.
            p = deepCopyMap(mapper,
                    (Map<String, Object>) wp01.get("w3cCredential"));
            p.put("validFrom", "2026-08-24T17:00:01Z");
            vectors.add(wpi("WPI03", "WP01",
                    "Projected validFrom differs from signed native validFrom",
                    "INVALID_PROJECTED_VALIDITY", p));

            // WPI04 -- projected issuance StateHash differs, native bytes intact.
            p = deepCopyMap(mapper,
                    (Map<String, Object>) wp01.get("w3cCredential"));
            byte[] wrongStateHash = Hex.decode((String) c01.get("issuanceStateHashHex"));
            wrongStateHash[wrongStateHash.length - 1] ^= 1;
            p.put("openIdentityIssuanceStateHash", multibaseBase58Btc(wrongStateHash));
            vectors.add(wpi("WPI04", "WP01",
                    "Projected issuance StateHash differs from signed native issuanceStateHash",
                    "INVALID_PROJECTED_ISSUANCE_STATE_HASH", p));

            // WPI05 -- corrupt embedded native SecuredCredential.
            p = deepCopyMap(mapper,
                    (Map<String, Object>) wp01.get("w3cCredential"));
            byte[] corruptSecured = Hex.decode((String) c01.get("securedCredentialHex"));
            corruptSecured[corruptSecured.length - 1] ^= 1;
            p.put("openIdentitySecuredCredential", multibaseBase64Url(corruptSecured));
            vectors.add(wpi("WPI05", "WP01",
                    "Embedded native SecuredCredential is corrupted",
                    "INVALID_NATIVE_SECURED_CREDENTIAL", p));

            // WPI06 -- projected subject identifier differs.
            p = deepCopyMap(mapper,
                    (Map<String, Object>) wp01.get("w3cCredential"));
            Map<String, Object> subj =
                    (Map<String, Object>) p.get("credentialSubject");
            subj.put("id", "urn:openidentity:test-subject:uYm9iQGV4YW1wbGUudGVzdA");
            vectors.add(wpi("WPI06", "WP01",
                    "Projected subject identifier differs from Basic v1 derivation",
                    "INVALID_PROJECTED_SUBJECT", p));

            // WPI07 -- projected signed claim differs.
            p = deepCopyMap(mapper,
                    (Map<String, Object>) wp01.get("w3cCredential"));
            subj = (Map<String, Object>) p.get("credentialSubject");
            subj.put("role", "administrator");
            vectors.add(wpi("WPI07", "WP01",
                    "Projected role claim differs from signed native claim",
                    "INVALID_PROJECTED_CLAIMS", p));

            // WPI08 -- required OpenIdentity /ns/v2 context replaced by frozen v1.
            p = deepCopyMap(mapper,
                    (Map<String, Object>) wp01.get("w3cCredential"));
            List<String> badContexts = new ArrayList<>(
                    (List<String>) p.get("@context"));
            badContexts.set(1, "https://openidentity.foundation/ns/v1");
            p.put("@context", badContexts);
            vectors.add(wpi("WPI08", "WP01",
                    "Projection uses unsupported OpenIdentity v1 context instead of required v2",
                    "UNSUPPORTED_PROJECTION_CONTEXT", p));

            // WPI09 -- misleading W3C proof claims native material is a
            // DataIntegrityProof. v0.1 projection explicitly forbids this.
            p = deepCopyMap(mapper,
                    (Map<String, Object>) wp01.get("w3cCredential"));
            Map<String, Object> fakeProof = new LinkedHashMap<>();
            fakeProof.put("type", "DataIntegrityProof");
            fakeProof.put("cryptosuite", "openidentity-cbor-2026");
            fakeProof.put("proofPurpose", "assertionMethod");
            fakeProof.put("proofValue", "uNOT-A-W3C-DATA-INTEGRITY-PROOF");
            p.put("proof", fakeProof);
            vectors.add(wpi("WPI09", "WP01",
                    "Projection misleadingly represents native OI-003 proof as W3C DataIntegrityProof",
                    "MISLEADING_W3C_PROOF", p));

            // WPI10 -- current-state substitution attack. The W3C fields and
            // embedded C01 remain unchanged, but verifier metadata supplies A02
            // as the state to use instead of C01's exact historical A01 state.
            p = deepCopyMap(mapper,
                    (Map<String, Object>) wp01.get("w3cCredential"));
            Map<String, Object> wpi10 = wpi("WPI10", "WP01",
                    "Verifier substitutes current assertion authority for issuanceStateHash-bound historical authority",
                    "HISTORICAL_ASSERTION_AUTHORITY_REQUIRED", p);
            put(wpi10, "requiredHistoricalStateHashHex",
                    Hex.decode((String) c01.get("issuanceStateHashHex")));
            // C02 is A04, so use the A02 state embedded in the existing assertion
            // authority vector generated earlier.
            Map<String, Object> a02Doc = mapper.readValue(
                    gen.resolve("assertion-a02-java.json").toFile(), Map.class);
            Map<String, Object> a02 = (Map<String, Object>) a02Doc.get("vector");
            put(wpi10, "substitutedCurrentStateHashHex",
                    Hex.decode((String) a02.get("resultingStateHashHex")));
            put(wpi10, "substitutedCurrentIdentityStateHex",
                    Hex.decode((String) a02.get("resultingIdentityStateHex")));
            wpi10.put("requiredHistoricalAssertionVector", "A01");
            wpi10.put("substitutedAssertionVector", "A02");
            vectors.add(wpi10);

            Map<String, Object> doc = new LinkedHashMap<>();
            doc.put("specification", "OpenIdentity W3C Credential Projection");
            doc.put("version", "0.1");
            doc.put("type", "invalid-conformance-vectors");
            doc.put("projectionVersion", 1);
            doc.put("vectors", vectors);

            mapper.writerWithDefaultPrettyPrinter().writeValue(
                    gen.resolve("w3c-credential-invalid-java.json").toFile(), doc);

            for (int i = 1; i <= 10; i++)
                success(String.format("WPI%02d generated", i));
            success("WPI01-WPI10 generated");
            success("w3c-credential-invalid-java.json");
            blankLine();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Unable to generate invalid W3C credential projection vectors", e);
        }
    }

    private static Map<String, Object> wpi(
            String id, String source, String description,
            String expectedError, Map<String, Object> projection) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", id);
        v.put("sourceProjectionVector", source);
        v.put("description", description);
        v.put("expectedError", expectedError);
        v.put("w3cCredential", projection);
        return v;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> deepCopyMap(
            ObjectMapper mapper, Map<String, Object> value) {
        return mapper.convertValue(value, LinkedHashMap.class);
    }


    /**
     * Consolidates WP01-WP02 and WPI01-WPI10 into the normative
     * W3C credential projection v0.1 bundle and hashes the exact JSON bytes.
     */
    @SuppressWarnings("unchecked")
    private static void generateNormativeW3cCredentialProjectionFile() {
        section("NORMATIVE", "Consolidating OI-003 W3C credential projection vectors");
        try {
            Path root = Path.of("..", "..").toAbsolutePath().normalize();
            Path gen = root.resolve("test-vectors").resolve("generated");
            Path tv = root.resolve("test-vectors");
            ObjectMapper mapper = new ObjectMapper();

            List<Map<String, Object>> valid = new ArrayList<>();
            for (String name : List.of(
                    "w3c-credential-wp01-java.json",
                    "w3c-credential-wp02-java.json")) {
                Map<String, Object> d =
                        mapper.readValue(gen.resolve(name).toFile(), Map.class);

                if (!"OpenIdentity W3C Credential Projection".equals(
                        d.get("specification"))
                        || !"0.1".equals(d.get("version"))) {
                    throw new IllegalStateException(
                            name + " has unexpected projection suite metadata");
                }

                Object raw = d.get("vector");
                if (!(raw instanceof Map<?, ?>)) {
                    throw new IllegalStateException(
                            name + " missing vector object");
                }

                Map<String, Object> vector = (Map<String, Object>) raw;
                if (!Integer.valueOf(1).equals(vector.get("projectionVersion"))) {
                    throw new IllegalStateException(
                            name + " has unexpected projectionVersion");
                }
                valid.add(vector);
            }

            List<String> validIds = valid.stream()
                    .map(v -> (String) v.get("id"))
                    .toList();
            if (!validIds.equals(List.of("WP01", "WP02"))) {
                throw new IllegalStateException(
                        "Unexpected W3C projection valid vector IDs: " + validIds);
            }

            Map<String, Object> invalidDoc = mapper.readValue(
                    gen.resolve("w3c-credential-invalid-java.json").toFile(),
                    Map.class);

            if (!"OpenIdentity W3C Credential Projection".equals(
                    invalidDoc.get("specification"))
                    || !"0.1".equals(invalidDoc.get("version"))
                    || !"invalid-conformance-vectors".equals(
                    invalidDoc.get("type"))
                    || !Integer.valueOf(1).equals(
                    invalidDoc.get("projectionVersion"))) {
                throw new IllegalStateException(
                        "w3c-credential-invalid-java.json has unexpected suite metadata");
            }

            Object rawInvalid = invalidDoc.get("vectors");
            if (!(rawInvalid instanceof List<?>)) {
                throw new IllegalStateException(
                        "w3c-credential-invalid-java.json missing vectors array");
            }
            List<Map<String, Object>> invalid =
                    (List<Map<String, Object>>) rawInvalid;

            List<String> expectedInvalid =
                    java.util.stream.IntStream.rangeClosed(1, 10)
                            .mapToObj(i -> String.format("WPI%02d", i))
                            .toList();
            List<String> actualInvalid = invalid.stream()
                    .map(v -> (String) v.get("id"))
                    .toList();

            if (!actualInvalid.equals(expectedInvalid)) {
                throw new IllegalStateException(
                        "Unexpected W3C projection invalid vector IDs: "
                                + actualInvalid);
            }

            Map<String, Object> normative = new LinkedHashMap<>();
            normative.put(
                    "specification",
                    "OpenIdentity W3C Credential Projection");
            normative.put("version", "0.1");
            normative.put("projectionVersion", 1);
            normative.put(
                    "openIdentityContext",
                    "https://openidentity.foundation/ns/v2");
            normative.put(
                    "credentialProfile",
                    "https://openidentity.foundation/test/credentials/basic/v1");
            normative.put("validVectors", valid);
            normative.put("invalidVectors", invalid);

            ObjectMapper output = new ObjectMapper()
                    .enable(SerializationFeature.INDENT_OUTPUT);

            Path jsonFile =
                    tv.resolve("w3c-credential-projection-v0.1.json");
            output.writeValue(jsonFile.toFile(), normative);

            byte[] jsonBytes = Files.readAllBytes(jsonFile);
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(jsonBytes);
            String sha256 = Hex.encode(digest);

            Path checksumFile =
                    tv.resolve("w3c-credential-projection-v0.1.json.sha256");
            Files.writeString(
                    checksumFile,
                    sha256 + "  w3c-credential-projection-v0.1.json\n");

            success("WP01-WP02 consolidated");
            success("WPI01-WPI10 consolidated");
            success("w3c-credential-projection-v0.1.json");
            success("SHA-256 " + sha256);
            success("w3c-credential-projection-v0.1.json.sha256");
            blankLine();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Unable to generate normative OI-003 W3C credential projection vector file",
                    e);
        }
    }


    /**
     * R01 -- first OI-007 RECOVER vector.
     *
     * Source state:
     *   IdentityState v1, ACTIVE, sequence 1
     *   V02 hybrid ControllerPolicy
     *   committed THRESHOLD 2-of-2 recovery authority using B keys
     *
     * Recovery:
     *   recovery authority = Ed25519 B + ML-DSA-65 B, threshold 2-of-2
     *   replacement controller = SINGLE Ed25519 C
     *   next recovery authority = SINGLE Ed25519 A
     *
     * Result:
     *   same identity, sequence 2, ACTIVE
     *   replacement ControllerPolicy installed
     *   recoveryCommitment rotated
     */
    private static void generateR01(HybridCreateResult v02) {
        section("R01", "THRESHOLD 2-of-2 RECOVER with recovery commitment rotation");

        // Current hidden recovery authority: B Ed25519 + B ML-DSA-65.
        var recoveryEd = new Ed25519Support(TestKeys.ED25519_SEED_B);
        var recoveryMl = new MlDsa65Support(TestKeys.ML_DSA_SEED_B);

        var recoveryEdMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID_B,
                OpenIdentityCbor.ed25519CoseKey(recoveryEd.publicKey()));
        var recoveryMlMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ML_DSA_METHOD_ID_B,
                OpenIdentityCbor.mlDsa65CoseKey(recoveryMl.publicKey()));

        // Reverse input order deliberately; RecoveryPolicy encoder must canonicalize.
        byte[] currentRecoveryPolicy = OpenIdentityCbor.recoveryThresholdPolicy(
                2, List.of(recoveryMlMethod, recoveryEdMethod));
        byte[] currentRecoveryCommitment =
                OpenIdentityCbor.recoveryCommitment(currentRecoveryPolicy);

        // Construct the authoritative source state carrying only the commitment.
        byte[] previousState = OpenIdentityCbor.identityState(
                1,
                TestKeys.IDENTITY,
                1,
                1,
                v02.controllerPolicy(),
                currentRecoveryCommitment,
                null);
        byte[] previousStateHash = StateHash.sha256Multihash(previousState);

        // Replacement controller: SINGLE Ed25519 C.
        var newController = new Ed25519Support(TestKeys.ED25519_SEED_C);
        var newControllerMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID_C,
                OpenIdentityCbor.ed25519CoseKey(newController.publicKey()));
        byte[] newControllerPolicy =
                OpenIdentityCbor.singlePolicy(newControllerMethod);

        // Next hidden recovery authority: SINGLE Ed25519 A.
        var nextRecovery = new Ed25519Support(TestKeys.ED25519_SEED);
        var nextRecoveryMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID,
                OpenIdentityCbor.ed25519CoseKey(nextRecovery.publicKey()));
        byte[] nextRecoveryPolicy =
                OpenIdentityCbor.recoverySinglePolicy(nextRecoveryMethod);
        byte[] newRecoveryCommitment =
                OpenIdentityCbor.recoveryCommitment(nextRecoveryPolicy);

        if (Arrays.equals(currentRecoveryCommitment, newRecoveryCommitment))
            throw new IllegalStateException(
                    "R01 new recovery commitment must differ from current commitment");

        byte[] operation = OpenIdentityCbor.recoverOperation(
                TestKeys.IDENTITY,
                2,
                previousStateHash,
                newControllerPolicy,
                currentRecoveryPolicy,
                newRecoveryCommitment);

        // Recovery authorization uses its own method-bound signing domain.
        byte[] recoveryEdInput = OpenIdentityCbor.recoveryProofSigningInput(
                operation, TestKeys.ED25519_METHOD_ID_B);
        byte[] recoveryMlInput = OpenIdentityCbor.recoveryProofSigningInput(
                operation, TestKeys.ML_DSA_METHOD_ID_B);

        byte[] recoveryEdSig = recoveryEd.sign(recoveryEdInput);
        byte[] recoveryMlSig = recoveryMl.sign(recoveryMlInput);

        if (!recoveryEd.verify(recoveryEdInput, recoveryEdSig)
                || !recoveryMl.verify(recoveryMlInput, recoveryMlSig))
            throw new IllegalStateException("R01 recovery authorization failed");

        var recoveryEdProof = OpenIdentityCbor.recoveryProof(
                TestKeys.ED25519_METHOD_ID_B, recoveryEdSig);
        var recoveryMlProof = OpenIdentityCbor.recoveryProof(
                TestKeys.ML_DSA_METHOD_ID_B, recoveryMlSig);

        // The replacement controller separately proves possession.
        byte[] newControllerPopInput =
                OpenIdentityCbor.controllerProofSigningInput(
                        operation, TestKeys.ED25519_METHOD_ID_C);
        byte[] newControllerPopSig =
                newController.sign(newControllerPopInput);

        if (!newController.verify(newControllerPopInput, newControllerPopSig))
            throw new IllegalStateException(
                    "R01 replacement-controller proof of possession failed");

        var newControllerPop = OpenIdentityCbor.controllerProof(
                TestKeys.ED25519_METHOD_ID_C, newControllerPopSig);

        // RECOVER: field 2 absent, field 3 controller PoP, field 4 recovery proofs.
        // Reverse recovery proof input order to exercise canonical ordering.
        byte[] signed = OpenIdentityCbor.signedOperation(
                operation,
                List.of(),
                List.of(newControllerPop),
                List.of(recoveryMlProof, recoveryEdProof));

        byte[] resultState = OpenIdentityCbor.identityState(
                1,
                TestKeys.IDENTITY,
                2,
                1,
                newControllerPolicy,
                newRecoveryCommitment,
                null);
        byte[] resultHash = StateHash.sha256Multihash(resultState);

        if (Arrays.equals(previousStateHash, resultHash))
            throw new IllegalStateException(
                    "R01 resulting StateHash unexpectedly equals predecessor");

        requireLength("R01 current recovery commitment",
                currentRecoveryCommitment, 34);
        requireLength("R01 new recovery commitment",
                newRecoveryCommitment, 34);
        requireLength("R01 previous StateHash", previousStateHash, 34);
        requireLength("R01 resulting StateHash", resultHash, 34);
        requireLength("R01 Ed25519 recovery signature", recoveryEdSig, 64);
        requireLength("R01 ML-DSA-65 recovery signature", recoveryMlSig, 3309);
        requireLength("R01 new-controller PoP signature",
                newControllerPopSig, 64);

        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", "R01");
        v.put("description",
                "THRESHOLD 2-of-2 recovery installs SINGLE Ed25519 controller and rotates recovery commitment");
        v.put("wireProtocolVersion", 1);
        v.put("sourceIdentityStateVersion", 1);
        v.put("resultingIdentityStateVersion", 1);
        v.put("sourceStatus", "ACTIVE");
        v.put("resultingStatus", "ACTIVE");
        v.put("sequence", 2);

        put(v, "identityHex", TestKeys.IDENTITY);
        put(v, "previousIdentityStateHex", previousState);
        put(v, "previousStateHashHex", previousStateHash);
        put(v, "previousControllerPolicyHex", v02.controllerPolicy());

        put(v, "currentRecoveryEd25519MethodIdHex",
                TestKeys.ED25519_METHOD_ID_B);
        put(v, "currentRecoveryMlDsa65MethodIdHex",
                TestKeys.ML_DSA_METHOD_ID_B);
        put(v, "currentRecoveryEd25519PublicKeyHex", recoveryEd.publicKey());
        put(v, "currentRecoveryMlDsa65PublicKeyHex", recoveryMl.publicKey());
        put(v, "currentRecoveryPolicyHex", currentRecoveryPolicy);
        put(v, "currentRecoveryCommitmentHex", currentRecoveryCommitment);
        v.put("recoveryPolicyType", "THRESHOLD");
        v.put("recoveryThreshold", 2);
        v.put("recoveryMethodCount", 2);

        put(v, "newControllerMethodIdHex", TestKeys.ED25519_METHOD_ID_C);
        put(v, "newControllerPublicKeyHex", newController.publicKey());
        put(v, "newControllerPolicyHex", newControllerPolicy);

        // The next policy is included as vector evidence so an independent
        // verifier can recompute the new commitment. It is not part of
        // OperationBytes and is not stored in resulting IdentityState.
        put(v, "nextRecoveryPolicyHex", nextRecoveryPolicy);
        put(v, "newRecoveryCommitmentHex", newRecoveryCommitment);

        put(v, "operationBytesHex", operation);

        put(v, "recoveryEd25519SigningInputHex", recoveryEdInput);
        put(v, "recoveryMlDsa65SigningInputHex", recoveryMlInput);
        put(v, "recoveryEd25519SignatureHex", recoveryEdSig);
        put(v, "recoveryMlDsa65SignatureHex", recoveryMlSig);
        put(v, "recoveryEd25519ProofHex", recoveryEdProof.encoded());
        put(v, "recoveryMlDsa65ProofHex", recoveryMlProof.encoded());

        put(v, "newControllerPopSigningInputHex", newControllerPopInput);
        put(v, "newControllerPopSignatureHex", newControllerPopSig);
        put(v, "newControllerProofHex", newControllerPop.encoded());

        put(v, "signedOperationHex", signed);
        put(v, "resultingIdentityStateHex", resultState);
        put(v, "resultingStateHashHex", resultHash);

        v.put("ordinaryAuthorizationProofCount", 0);
        v.put("controllerProofCount", 1);
        v.put("recoveryProofCount", 2);
        v.put("inputRecoveryProofOrder",
                List.of("ML-DSA-65", "Ed25519"));
        v.put("canonicalRecoveryProofOrder",
                List.of("Ed25519", "ML-DSA-65"));
        v.put("recoveryCommitmentRotated", true);
        v.put("identityPreserved", true);

        Map<String, Object> d = new LinkedHashMap<>();
        d.put("specification", "OpenIdentity Recovery");
        d.put("version", "0.1");
        d.put("wireProtocolVersion", 1);
        d.put("vector", v);

        writeJson("recovery-r01-java.json", d);

        success("Current RecoveryPolicy commitment generated");
        success("RecoveryPolicy THRESHOLD 2-of-2 authorization verified");
        success("Ordinary ControllerPolicy authorization omitted");
        success("Replacement controller proof-of-possession verified");
        success("Recovery proof input canonically ordered");
        success("Recovery commitment rotated");
        success("Identity preserved and sequence incremented");
        success("Resulting ACTIVE IdentityState and StateHash generated");
        success("recovery-r01-java.json");
        blankLine();
    }


    /**
     * OI-007 recovery invalid/security vectors RI01-RI10.
     *
     * These deliberately construct invalid semantic cases. Raw encoders are
     * used where the canonical OpenIdentityCbor API correctly refuses the
     * malformed object.
     */
    private static void generateRecoveryInvalidVectors(HybridCreateResult v02) {
        section("RECOVERY INVALID", "RI01-RI10");

        var recoveryEd = new Ed25519Support(TestKeys.ED25519_SEED_B);
        var recoveryMl = new MlDsa65Support(TestKeys.ML_DSA_SEED_B);
        var newController = new Ed25519Support(TestKeys.ED25519_SEED_C);
        var unauthorized = new Ed25519Support(TestKeys.ED25519_SEED);

        var recoveryEdMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID_B,
                OpenIdentityCbor.ed25519CoseKey(recoveryEd.publicKey()));
        var recoveryMlMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ML_DSA_METHOD_ID_B,
                OpenIdentityCbor.mlDsa65CoseKey(recoveryMl.publicKey()));

        byte[] recoveryPolicy = OpenIdentityCbor.recoveryThresholdPolicy(
                2, List.of(recoveryMlMethod, recoveryEdMethod));
        byte[] recoveryCommitment =
                OpenIdentityCbor.recoveryCommitment(recoveryPolicy);

        byte[] sourceState = OpenIdentityCbor.identityState(
                1, TestKeys.IDENTITY, 1, 1,
                v02.controllerPolicy(), recoveryCommitment, null);
        byte[] sourceHash = StateHash.sha256Multihash(sourceState);

        var newControllerMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID_C,
                OpenIdentityCbor.ed25519CoseKey(newController.publicKey()));
        byte[] newControllerPolicy =
                OpenIdentityCbor.singlePolicy(newControllerMethod);

        var nextRecoveryMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID,
                OpenIdentityCbor.ed25519CoseKey(unauthorized.publicKey()));
        byte[] nextRecoveryPolicy =
                OpenIdentityCbor.recoverySinglePolicy(nextRecoveryMethod);
        byte[] nextCommitment =
                OpenIdentityCbor.recoveryCommitment(nextRecoveryPolicy);

        byte[] validOperation = OpenIdentityCbor.recoverOperation(
                TestKeys.IDENTITY, 2, sourceHash,
                newControllerPolicy, recoveryPolicy, nextCommitment);

        byte[] edRecoveryInput = OpenIdentityCbor.recoveryProofSigningInput(
                validOperation, TestKeys.ED25519_METHOD_ID_B);
        byte[] mlRecoveryInput = OpenIdentityCbor.recoveryProofSigningInput(
                validOperation, TestKeys.ML_DSA_METHOD_ID_B);
        var edRecoveryProof = OpenIdentityCbor.recoveryProof(
                TestKeys.ED25519_METHOD_ID_B,
                recoveryEd.sign(edRecoveryInput));
        var mlRecoveryProof = OpenIdentityCbor.recoveryProof(
                TestKeys.ML_DSA_METHOD_ID_B,
                recoveryMl.sign(mlRecoveryInput));

        byte[] popInput = OpenIdentityCbor.controllerProofSigningInput(
                validOperation, TestKeys.ED25519_METHOD_ID_C);
        var newControllerPop = OpenIdentityCbor.controllerProof(
                TestKeys.ED25519_METHOD_ID_C,
                newController.sign(popInput));

        List<Map<String,Object>> vectors = new ArrayList<>();

        // RI01 — source state has no recovery commitment.
        byte[] noRecoveryState = OpenIdentityCbor.identityState(
                1, TestKeys.IDENTITY, 1, 1,
                v02.controllerPolicy(), null, null);
        byte[] noRecoveryHash = StateHash.sha256Multihash(noRecoveryState);
        byte[] ri01op = OpenIdentityCbor.recoverOperation(
                TestKeys.IDENTITY, 2, noRecoveryHash,
                newControllerPolicy, recoveryPolicy, nextCommitment);
        vectors.add(recoveryInvalid(
                "RI01", "RECOVER targets state with no recoveryCommitment",
                "RECOVERY_NOT_CONFIGURED", noRecoveryState, noRecoveryHash,
                ri01op, null));

        // RI02 — reveal a different valid RecoveryPolicy than the committed one.
        byte[] wrongPolicy = OpenIdentityCbor.recoverySinglePolicy(
                recoveryEdMethod);
        byte[] ri02op = OpenIdentityCbor.recoverOperation(
                TestKeys.IDENTITY, 2, sourceHash,
                newControllerPolicy, wrongPolicy, nextCommitment);
        vectors.add(recoveryInvalid(
                "RI02", "Revealed RecoveryPolicy does not match current commitment",
                "INVALID_RECOVERY_POLICY", sourceState, sourceHash,
                ri02op, null));

        // RI03 — malformed threshold 3-of-2, constructed raw.
        byte[] badThresholdPolicy = rawRecoveryThresholdPolicy(
                3, List.of(recoveryEdMethod, recoveryMlMethod));
        byte[] ri03op = rawRecoverOperationFull(
                TestKeys.IDENTITY, 2, sourceHash,
                newControllerPolicy, badThresholdPolicy, nextCommitment);
        vectors.add(recoveryInvalid(
                "RI03", "RecoveryPolicy threshold exceeds method count",
                "INVALID_RECOVERY_THRESHOLD", sourceState, sourceHash,
                ri03op, null));

        // RI04 — committed 2-of-2 policy but only one recovery proof.
        byte[] ri04signed = rawRecoverySignedOperation(
                validOperation,
                List.of(newControllerPop),
                List.of(edRecoveryProof));
        vectors.add(recoveryInvalid(
                "RI04", "Recovery threshold 2-of-2 receives only one proof",
                "RECOVERY_THRESHOLD_NOT_SATISFIED", sourceState, sourceHash,
                validOperation, ri04signed));

        // RI05 — duplicate recovery method proof ID.
        byte[] ri05signed = rawRecoverySignedOperation(
                validOperation,
                List.of(newControllerPop),
                List.of(edRecoveryProof, edRecoveryProof, mlRecoveryProof));
        vectors.add(recoveryInvalid(
                "RI05", "Recovery proof collection contains duplicate method ID",
                "DUPLICATE_RECOVERY_PROOF", sourceState, sourceHash,
                validOperation, ri05signed));

        // RI06 — extra valid signature from a method absent from RecoveryPolicy.
        byte[] unauthorizedInput = OpenIdentityCbor.recoveryProofSigningInput(
                validOperation, TestKeys.ED25519_METHOD_ID);
        var unauthorizedProof = OpenIdentityCbor.recoveryProof(
                TestKeys.ED25519_METHOD_ID,
                unauthorized.sign(unauthorizedInput));
        byte[] ri06signed = rawRecoverySignedOperation(
                validOperation,
                List.of(newControllerPop),
                List.of(edRecoveryProof, mlRecoveryProof, unauthorizedProof));
        Map<String,Object> ri06 = recoveryInvalid(
                "RI06", "Recovery proof uses method absent from committed RecoveryPolicy",
                "UNAUTHORIZED_RECOVERY_METHOD", sourceState, sourceHash,
                validOperation, ri06signed);
        put(ri06, "unauthorizedRecoveryMethodIdHex",
                TestKeys.ED25519_METHOD_ID);
        vectors.add(ri06);

        // RI07 — corrupt an otherwise authorized Ed25519 recovery signature.
        byte[] badRecoverySig = recoveryEd.sign(edRecoveryInput);
        badRecoverySig[0] ^= 1;
        var badRecoveryProof = OpenIdentityCbor.recoveryProof(
                TestKeys.ED25519_METHOD_ID_B, badRecoverySig);
        byte[] ri07signed = rawRecoverySignedOperation(
                validOperation,
                List.of(newControllerPop),
                List.of(badRecoveryProof, mlRecoveryProof));
        vectors.add(recoveryInvalid(
                "RI07", "Authorized recovery proof contains corrupted signature",
                "INVALID_RECOVERY_SIGNATURE", sourceState, sourceHash,
                validOperation, ri07signed));

        // RI08 — recovery authorization succeeds, but replacement controller PoP is absent.
        byte[] ri08signed = rawRecoverySignedOperation(
                validOperation,
                List.of(),
                List.of(edRecoveryProof, mlRecoveryProof));
        vectors.add(recoveryInvalid(
                "RI08", "Replacement controller is missing proof of possession",
                "MISSING_PROOF_OF_POSSESSION", sourceState, sourceHash,
                validOperation, ri08signed));

        // RI09 — operation proposes the exact current recovery commitment again.
        byte[] ri09op = OpenIdentityCbor.recoverOperation(
                TestKeys.IDENTITY, 2, sourceHash,
                newControllerPolicy, recoveryPolicy, recoveryCommitment);
        byte[] ri09EdIn = OpenIdentityCbor.recoveryProofSigningInput(
                ri09op, TestKeys.ED25519_METHOD_ID_B);
        byte[] ri09MlIn = OpenIdentityCbor.recoveryProofSigningInput(
                ri09op, TestKeys.ML_DSA_METHOD_ID_B);
        var ri09Ed = OpenIdentityCbor.recoveryProof(
                TestKeys.ED25519_METHOD_ID_B, recoveryEd.sign(ri09EdIn));
        var ri09Ml = OpenIdentityCbor.recoveryProof(
                TestKeys.ML_DSA_METHOD_ID_B, recoveryMl.sign(ri09MlIn));
        byte[] ri09PopIn = OpenIdentityCbor.controllerProofSigningInput(
                ri09op, TestKeys.ED25519_METHOD_ID_C);
        var ri09Pop = OpenIdentityCbor.controllerProof(
                TestKeys.ED25519_METHOD_ID_C, newController.sign(ri09PopIn));
        byte[] ri09signed = rawRecoverySignedOperation(
                ri09op, List.of(ri09Pop), List.of(ri09Ed, ri09Ml));
        vectors.add(recoveryInvalid(
                "RI09", "RECOVER reuses current recoveryCommitment",
                "INVALID_RECOVERY_COMMITMENT", sourceState, sourceHash,
                ri09op, ri09signed));

        // RI10 — signatures are cryptographically valid in the ordinary
        // operation domain, but invalid in the required recovery domain.
        byte[] wrongDomain = OpenIdentityCbor.operationSigningInput(validOperation);
        var wrongEd = OpenIdentityCbor.recoveryProof(
                TestKeys.ED25519_METHOD_ID_B, recoveryEd.sign(wrongDomain));
        var wrongMl = OpenIdentityCbor.recoveryProof(
                TestKeys.ML_DSA_METHOD_ID_B, recoveryMl.sign(wrongDomain));
        byte[] ri10signed = rawRecoverySignedOperation(
                validOperation,
                List.of(newControllerPop),
                List.of(wrongEd, wrongMl));
        Map<String,Object> ri10 = recoveryInvalid(
                "RI10", "Recovery proofs use ordinary operation signing domain",
                "INVALID_RECOVERY_SIGNATURE", sourceState, sourceHash,
                validOperation, ri10signed);
        put(ri10, "wrongSigningInputHex", wrongDomain);
        put(ri10, "requiredEd25519RecoverySigningInputHex", edRecoveryInput);
        put(ri10, "requiredMlDsa65RecoverySigningInputHex", mlRecoveryInput);
        vectors.add(ri10);

        List<String> ids = vectors.stream()
                .map(v -> (String)v.get("id")).toList();
        List<String> expected = java.util.stream.IntStream.rangeClosed(1,10)
                .mapToObj(i -> String.format("RI%02d", i)).toList();
        if (!ids.equals(expected))
            throw new IllegalStateException("Unexpected recovery invalid IDs: " + ids);

        Map<String,Object> doc = new LinkedHashMap<>();
        doc.put("specification", "OpenIdentity Recovery");
        doc.put("version", "0.1");
        doc.put("type", "invalid-conformance-vectors");
        doc.put("wireProtocolVersion", 1);
        doc.put("vectors", vectors);
        writeJson("recovery-invalid-java.json", doc);

        for (int i=1;i<=10;i++) success(String.format("RI%02d generated", i));
        success("RI01-RI10 generated");
        success("recovery-invalid-java.json");
        blankLine();
    }

    private static Map<String,Object> recoveryInvalid(
            String id, String description, String expectedError,
            byte[] previousState, byte[] previousStateHash,
            byte[] operation, byte[] signedOperation) {
        Map<String,Object> v = new LinkedHashMap<>();
        v.put("id", id);
        v.put("description", description);
        v.put("expectedError", expectedError);
        put(v, "identityHex", TestKeys.IDENTITY);
        put(v, "previousIdentityStateHex", previousState);
        put(v, "previousStateHashHex", previousStateHash);
        put(v, "operationBytesHex", operation);
        if (signedOperation != null)
            put(v, "signedOperationHex", signedOperation);
        return v;
    }

    private static byte[] rawRecoveryThresholdPolicy(
            int threshold,
            List<OpenIdentityCbor.EncodedVerificationMethod> methods) {
        var sorted = new ArrayList<>(methods);
        sorted.sort((a,b) -> compareUnsignedBytes(a.id(), b.id()));
        var c = new DeterministicCborWriter();
        c.writeMapHeader(4);
        c.writeUnsigned(1); c.writeUnsigned(1);
        c.writeUnsigned(2); c.writeUnsigned(2);
        c.writeUnsigned(3); c.writeUnsigned(threshold);
        c.writeUnsigned(4); c.writeArrayHeader(sorted.size());
        for (var m : sorted) c.writeEncoded(m.encoded());
        return c.toByteArray();
    }

    private static byte[] rawRecoverOperationFull(
            byte[] identity, long sequence, byte[] previousStateHash,
            byte[] newControllerPolicy, byte[] recoveryPolicy,
            byte[] newRecoveryCommitment) {
        var p = new DeterministicCborWriter();
        p.writeMapHeader(3);
        p.writeUnsigned(1); p.writeEncoded(newControllerPolicy);
        p.writeUnsigned(2); p.writeEncoded(recoveryPolicy);
        p.writeUnsigned(3); p.writeByteString(newRecoveryCommitment);

        var c = new DeterministicCborWriter();
        c.writeMapHeader(6);
        c.writeUnsigned(1); c.writeUnsigned(1);
        c.writeUnsigned(2); c.writeUnsigned(3);
        c.writeUnsigned(3); c.writeByteString(identity);
        c.writeUnsigned(4); c.writeUnsigned(sequence);
        c.writeUnsigned(5); c.writeByteString(previousStateHash);
        c.writeUnsigned(6); c.writeEncoded(p.toByteArray());
        return c.toByteArray();
    }

    /**
     * Raw RECOVER envelope used to construct invalid proof-set vectors.
     * Field 2 is deliberately absent. Fields 3/4 are emitted only when nonempty.
     */
    private static byte[] rawRecoverySignedOperation(
            byte[] operation,
            List<OpenIdentityCbor.EncodedProof> controllerProofs,
            List<OpenIdentityCbor.EncodedProof> recoveryProofs) {
        int fields = 1
                + (controllerProofs.isEmpty() ? 0 : 1)
                + (recoveryProofs.isEmpty() ? 0 : 1);
        var c = new DeterministicCborWriter();
        c.writeMapHeader(fields);
        c.writeUnsigned(1); c.writeEncoded(operation);
        if (!controllerProofs.isEmpty()) {
            c.writeUnsigned(3);
            c.writeArrayHeader(controllerProofs.size());
            for (var p : controllerProofs) c.writeEncoded(p.encoded());
        }
        if (!recoveryProofs.isEmpty()) {
            c.writeUnsigned(4);
            c.writeArrayHeader(recoveryProofs.size());
            for (var p : recoveryProofs) c.writeEncoded(p.encoded());
        }
        return c.toByteArray();
    }


    /**
     * R02 -- recover a DEACTIVATED IdentityState v2 and preserve AssertionPolicy.
     *
     * This vector joins the OI-006 lifecycle rule with OI-007 recovery:
     * ordinary controller authority cannot reactivate a deactivated identity,
     * but valid independent RecoveryPolicy authority can.
     */
    private static void generateR02(
            HybridCreateResult v02,
            AssertionStateResult a04) {
        section("R02", "DEACTIVATED v2 -> RECOVER -> ACTIVE v2 with AssertionPolicy preserved");

        // Current recovery authority: THRESHOLD 2-of-2 using B keys.
        var recoveryEd = new Ed25519Support(TestKeys.ED25519_SEED_B);
        var recoveryMl = new MlDsa65Support(TestKeys.ML_DSA_SEED_B);
        var recoveryEdMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID_B,
                OpenIdentityCbor.ed25519CoseKey(recoveryEd.publicKey()));
        var recoveryMlMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ML_DSA_METHOD_ID_B,
                OpenIdentityCbor.mlDsa65CoseKey(recoveryMl.publicKey()));
        byte[] recoveryPolicy = OpenIdentityCbor.recoveryThresholdPolicy(
                2, List.of(recoveryMlMethod, recoveryEdMethod));
        byte[] currentRecoveryCommitment =
                OpenIdentityCbor.recoveryCommitment(recoveryPolicy);

        // A04 is IdentityState v2 sequence 5 with hybrid AssertionPolicy.
        // Model the subsequent OI-006 DEACTIVATE result at sequence 6.
        byte[] deactivatedState = OpenIdentityCbor.identityState(
                2,
                TestKeys.IDENTITY,
                6,
                2, // DEACTIVATED
                v02.controllerPolicy(),
                currentRecoveryCommitment,
                a04.assertionPolicy());
        byte[] deactivatedStateHash =
                StateHash.sha256Multihash(deactivatedState);

        // Replacement controller: SINGLE Ed25519 C.
        var newController = new Ed25519Support(TestKeys.ED25519_SEED_C);
        var newControllerMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID_C,
                OpenIdentityCbor.ed25519CoseKey(newController.publicKey()));
        byte[] newControllerPolicy =
                OpenIdentityCbor.singlePolicy(newControllerMethod);

        // Rotate recovery authority to SINGLE Ed25519 A.
        var nextRecovery = new Ed25519Support(TestKeys.ED25519_SEED);
        var nextRecoveryMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID,
                OpenIdentityCbor.ed25519CoseKey(nextRecovery.publicKey()));
        byte[] nextRecoveryPolicy =
                OpenIdentityCbor.recoverySinglePolicy(nextRecoveryMethod);
        byte[] newRecoveryCommitment =
                OpenIdentityCbor.recoveryCommitment(nextRecoveryPolicy);

        if (Arrays.equals(currentRecoveryCommitment, newRecoveryCommitment))
            throw new IllegalStateException(
                    "R02 recovery commitment did not rotate");

        byte[] operation = OpenIdentityCbor.recoverOperation(
                TestKeys.IDENTITY,
                7,
                deactivatedStateHash,
                newControllerPolicy,
                recoveryPolicy,
                newRecoveryCommitment);

        // Independent recovery authorization.
        byte[] edRecoveryInput =
                OpenIdentityCbor.recoveryProofSigningInput(
                        operation, TestKeys.ED25519_METHOD_ID_B);
        byte[] mlRecoveryInput =
                OpenIdentityCbor.recoveryProofSigningInput(
                        operation, TestKeys.ML_DSA_METHOD_ID_B);
        byte[] edRecoverySig = recoveryEd.sign(edRecoveryInput);
        byte[] mlRecoverySig = recoveryMl.sign(mlRecoveryInput);

        if (!recoveryEd.verify(edRecoveryInput, edRecoverySig)
                || !recoveryMl.verify(mlRecoveryInput, mlRecoverySig))
            throw new IllegalStateException(
                    "R02 recovery authorization failed");

        var edRecoveryProof = OpenIdentityCbor.recoveryProof(
                TestKeys.ED25519_METHOD_ID_B, edRecoverySig);
        var mlRecoveryProof = OpenIdentityCbor.recoveryProof(
                TestKeys.ML_DSA_METHOD_ID_B, mlRecoverySig);

        // Replacement controller proves possession.
        byte[] popInput = OpenIdentityCbor.controllerProofSigningInput(
                operation, TestKeys.ED25519_METHOD_ID_C);
        byte[] popSig = newController.sign(popInput);
        if (!newController.verify(popInput, popSig))
            throw new IllegalStateException(
                    "R02 replacement-controller PoP failed");
        var pop = OpenIdentityCbor.controllerProof(
                TestKeys.ED25519_METHOD_ID_C, popSig);

        // No ordinary authorization proofs. Reverse recovery proof input order.
        byte[] signed = OpenIdentityCbor.signedOperation(
                operation,
                List.of(),
                List.of(pop),
                List.of(mlRecoveryProof, edRecoveryProof));

        // RECOVER reactivates, preserves v2 and exact AssertionPolicy.
        byte[] resultState = OpenIdentityCbor.identityState(
                2,
                TestKeys.IDENTITY,
                7,
                1, // ACTIVE
                newControllerPolicy,
                newRecoveryCommitment,
                a04.assertionPolicy());
        byte[] resultHash = StateHash.sha256Multihash(resultState);

        if (Arrays.equals(deactivatedStateHash, resultHash))
            throw new IllegalStateException(
                    "R02 resulting StateHash unexpectedly equals predecessor");

        requireLength("R02 predecessor StateHash", deactivatedStateHash, 34);
        requireLength("R02 resulting StateHash", resultHash, 34);
        requireLength("R02 current recovery commitment",
                currentRecoveryCommitment, 34);
        requireLength("R02 new recovery commitment",
                newRecoveryCommitment, 34);
        requireLength("R02 Ed25519 recovery signature", edRecoverySig, 64);
        requireLength("R02 ML-DSA-65 recovery signature", mlRecoverySig, 3309);
        requireLength("R02 replacement-controller PoP signature", popSig, 64);

        Map<String,Object> v = new LinkedHashMap<>();
        v.put("id", "R02");
        v.put("description",
                "RECOVER reactivates DEACTIVATED IdentityState v2 while preserving AssertionPolicy");
        v.put("sourceAssertionVector", "A04");
        v.put("wireProtocolVersion", 1);
        v.put("sourceIdentityStateVersion", 2);
        v.put("resultingIdentityStateVersion", 2);
        v.put("sourceSequence", 6);
        v.put("sequence", 7);
        v.put("sourceStatus", "DEACTIVATED");
        v.put("resultingStatus", "ACTIVE");

        put(v, "identityHex", TestKeys.IDENTITY);
        put(v, "previousIdentityStateHex", deactivatedState);
        put(v, "previousStateHashHex", deactivatedStateHash);
        put(v, "previousControllerPolicyHex", v02.controllerPolicy());
        put(v, "preservedAssertionPolicyHex", a04.assertionPolicy());

        put(v, "currentRecoveryEd25519MethodIdHex",
                TestKeys.ED25519_METHOD_ID_B);
        put(v, "currentRecoveryMlDsa65MethodIdHex",
                TestKeys.ML_DSA_METHOD_ID_B);
        put(v, "currentRecoveryEd25519PublicKeyHex", recoveryEd.publicKey());
        put(v, "currentRecoveryMlDsa65PublicKeyHex", recoveryMl.publicKey());
        put(v, "currentRecoveryPolicyHex", recoveryPolicy);
        put(v, "currentRecoveryCommitmentHex", currentRecoveryCommitment);
        v.put("recoveryPolicyType", "THRESHOLD");
        v.put("recoveryThreshold", 2);

        put(v, "newControllerMethodIdHex", TestKeys.ED25519_METHOD_ID_C);
        put(v, "newControllerPublicKeyHex", newController.publicKey());
        put(v, "newControllerPolicyHex", newControllerPolicy);

        put(v, "nextRecoveryPolicyHex", nextRecoveryPolicy);
        put(v, "newRecoveryCommitmentHex", newRecoveryCommitment);
        put(v, "operationBytesHex", operation);

        put(v, "recoveryEd25519SigningInputHex", edRecoveryInput);
        put(v, "recoveryMlDsa65SigningInputHex", mlRecoveryInput);
        put(v, "recoveryEd25519SignatureHex", edRecoverySig);
        put(v, "recoveryMlDsa65SignatureHex", mlRecoverySig);
        put(v, "recoveryEd25519ProofHex", edRecoveryProof.encoded());
        put(v, "recoveryMlDsa65ProofHex", mlRecoveryProof.encoded());

        put(v, "newControllerPopSigningInputHex", popInput);
        put(v, "newControllerPopSignatureHex", popSig);
        put(v, "newControllerProofHex", pop.encoded());

        put(v, "signedOperationHex", signed);
        put(v, "resultingIdentityStateHex", resultState);
        put(v, "resultingStateHashHex", resultHash);

        v.put("ordinaryAuthorizationProofCount", 0);
        v.put("controllerProofCount", 1);
        v.put("recoveryProofCount", 2);
        v.put("identityPreserved", true);
        v.put("assertionPolicyPreserved", true);
        v.put("stateVersionPreserved", true);
        v.put("reactivatedByRecovery", true);
        v.put("recoveryCommitmentRotated", true);

        Map<String,Object> d = new LinkedHashMap<>();
        d.put("specification", "OpenIdentity Recovery");
        d.put("version", "0.1");
        d.put("wireProtocolVersion", 1);
        d.put("vector", v);
        writeJson("recovery-r02-java.json", d);

        success("DEACTIVATED IdentityState v2 used as authoritative predecessor");
        success("RecoveryPolicy THRESHOLD 2-of-2 authorization verified");
        success("Ordinary ControllerPolicy authorization omitted");
        success("Replacement controller proof-of-possession verified");
        success("DEACTIVATED identity reactivated to ACTIVE");
        success("IdentityState version v2 preserved");
        success("AssertionPolicy preserved exactly");
        success("Recovery commitment rotated");
        success("Identity preserved and sequence incremented");
        success("Resulting ACTIVE v2 IdentityState and StateHash generated");
        success("recovery-r02-java.json");
        blankLine();
    }


    /**
     * Consolidates OI-007 R01-R02 and RI01-RI10 into the normative
     * recovery-v0.1.json artifact and hashes the exact JSON bytes written.
     */
    @SuppressWarnings("unchecked")
    private static void generateNormativeRecoveryFile() {
        section("NORMATIVE", "Consolidating OI-007 recovery vectors");
        try {
            Path root = Path.of("..", "..").toAbsolutePath().normalize();
            Path gen = root.resolve("test-vectors").resolve("generated");
            Path tv = root.resolve("test-vectors");
            ObjectMapper mapper = new ObjectMapper();

            List<Map<String, Object>> valid = new ArrayList<>();
            for (String name : List.of(
                    "recovery-r01-java.json",
                    "recovery-r02-java.json")) {
                Map<String, Object> d = mapper.readValue(
                        gen.resolve(name).toFile(), Map.class);

                if (!"OpenIdentity Recovery".equals(d.get("specification"))
                        || !"0.1".equals(d.get("version"))
                        || !Integer.valueOf(1).equals(
                        d.get("wireProtocolVersion"))) {
                    throw new IllegalStateException(
                            name + " has unexpected recovery suite metadata");
                }

                Object raw = d.get("vector");
                if (!(raw instanceof Map<?, ?>)) {
                    throw new IllegalStateException(
                            name + " missing vector object");
                }
                valid.add((Map<String, Object>) raw);
            }

            List<String> validIds = valid.stream()
                    .map(v -> (String) v.get("id"))
                    .toList();
            if (!validIds.equals(List.of("R01", "R02"))) {
                throw new IllegalStateException(
                        "Unexpected OI-007 valid vector IDs: " + validIds);
            }

            Map<String, Object> invalidDoc = mapper.readValue(
                    gen.resolve("recovery-invalid-java.json").toFile(),
                    Map.class);

            if (!"OpenIdentity Recovery".equals(
                    invalidDoc.get("specification"))
                    || !"0.1".equals(invalidDoc.get("version"))
                    || !"invalid-conformance-vectors".equals(
                    invalidDoc.get("type"))
                    || !Integer.valueOf(1).equals(
                    invalidDoc.get("wireProtocolVersion"))) {
                throw new IllegalStateException(
                        "recovery-invalid-java.json has unexpected suite metadata");
            }

            Object rawInvalid = invalidDoc.get("vectors");
            if (!(rawInvalid instanceof List<?>)) {
                throw new IllegalStateException(
                        "recovery-invalid-java.json missing vectors array");
            }

            List<Map<String, Object>> invalid =
                    (List<Map<String, Object>>) rawInvalid;

            List<String> expectedInvalid =
                    java.util.stream.IntStream.rangeClosed(1, 10)
                            .mapToObj(i -> String.format("RI%02d", i))
                            .toList();
            List<String> actualInvalid = invalid.stream()
                    .map(v -> (String) v.get("id"))
                    .toList();

            if (!actualInvalid.equals(expectedInvalid)) {
                throw new IllegalStateException(
                        "Unexpected OI-007 invalid vector IDs: "
                                + actualInvalid);
            }

            Map<String, Object> recoveryCommitment = new LinkedHashMap<>();
            recoveryCommitment.put("multihashAlgorithm", "sha2-256");
            recoveryCommitment.put("multihashCode", 18);
            recoveryCommitment.put("digestLength", 32);
            recoveryCommitment.put("multihashLength", 34);
            recoveryCommitment.put(
                    "committedObject",
                    "deterministic CBOR RecoveryPolicyBytes");

            Map<String, Object> normative = new LinkedHashMap<>();
            normative.put("specification", "OpenIdentity Recovery");
            normative.put("version", "0.1");
            normative.put("wireProtocolVersion", 1);
            normative.put("recoveryPolicyVersion", 1);
            normative.put(
                    "recoverySigningDomain",
                    "OpenIdentity Recovery");
            normative.put(
                    "controllerProofSigningDomain",
                    "OpenIdentity Controller Proof");
            normative.put("recoveryCommitment", recoveryCommitment);
            normative.put("validVectors", valid);
            normative.put("invalidVectors", invalid);

            ObjectMapper output = new ObjectMapper()
                    .enable(SerializationFeature.INDENT_OUTPUT);

            Path jsonFile = tv.resolve("recovery-v0.1.json");
            output.writeValue(jsonFile.toFile(), normative);

            // Hash the exact bytes Jackson wrote to disk.
            byte[] jsonBytes = Files.readAllBytes(jsonFile);
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(jsonBytes);
            String sha256 = Hex.encode(digest);

            Path checksumFile =
                    tv.resolve("recovery-v0.1.json.sha256");
            Files.writeString(
                    checksumFile,
                    sha256 + "  recovery-v0.1.json\n");

            success("R01-R02 consolidated");
            success("RI01-RI10 consolidated");
            success("recovery-v0.1.json");
            success("SHA-256 " + sha256);
            success("recovery-v0.1.json.sha256");
            blankLine();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Unable to generate normative OI-007 recovery vector file",
                    e);
        }
    }



    /**
     * OI-010 SE01-SE10 signature-envelope and domain-separation vectors.
     *
     * SE01 is a positive ordinary authorization case. SE02-SE10 are
     * mutation/substitution security cases. The original SE01 signature is
     * intentionally reused where the test proves that changing covered
     * OperationBytes invalidates authorization.
     */
    private static void generateSignatureEnvelopeVectors(
            HybridCreateResult v02) {
        section("SIGNATURE ENVELOPE", "SE01-SE10");

        var controller = new Ed25519Support(TestKeys.ED25519_SEED);
        var proposed = new Ed25519Support(TestKeys.ED25519_SEED_B);
        var recovery = new Ed25519Support(TestKeys.ED25519_SEED_C);

        var controllerMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID,
                OpenIdentityCbor.ed25519CoseKey(controller.publicKey()));
        byte[] controllerPolicy =
                OpenIdentityCbor.singlePolicy(controllerMethod);

        var proposedMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID_B,
                OpenIdentityCbor.ed25519CoseKey(proposed.publicKey()));
        byte[] proposedPolicy =
                OpenIdentityCbor.singlePolicy(proposedMethod);

        // Base fixture is a valid ROTATE_CONTROLLER at sequence 2.
        byte[] operation = OpenIdentityCbor.rotateControllerOperation(
                TestKeys.IDENTITY, 2, v02.stateHash(), proposedPolicy);
        byte[] authInput = OpenIdentityCbor.operationSigningInput(operation);
        byte[] authSig = controller.sign(authInput);
        if (!controller.verify(authInput, authSig))
            throw new IllegalStateException("SE01 authorization failed");
        var authProof = OpenIdentityCbor.authorizationProof(
                TestKeys.ED25519_METHOD_ID, authSig);

        byte[] popInput = OpenIdentityCbor.controllerProofSigningInput(
                operation, TestKeys.ED25519_METHOD_ID_B);
        byte[] popSig = proposed.sign(popInput);
        if (!proposed.verify(popInput, popSig))
            throw new IllegalStateException("SE01 PoP failed");
        var popProof = OpenIdentityCbor.controllerProof(
                TestKeys.ED25519_METHOD_ID_B, popSig);

        byte[] signed = OpenIdentityCbor.signedOperation(
                operation, List.of(authProof), List.of(popProof));

        List<Map<String,Object>> vectors = new ArrayList<>();

        Map<String,Object> se01 = signatureEnvelopeVector(
                "SE01", "Valid ordinary controller authorization",
                "ACCEPT", operation);
        put(se01, "identityHex", TestKeys.IDENTITY);
        put(se01, "previousStateHashHex", v02.stateHash());
        put(se01, "controllerMethodIdHex", TestKeys.ED25519_METHOD_ID);
        put(se01, "controllerPublicKeyHex", controller.publicKey());
        put(se01, "proposedControllerMethodIdHex",
                TestKeys.ED25519_METHOD_ID_B);
        put(se01, "proposedControllerPublicKeyHex", proposed.publicKey());
        put(se01, "proposedControllerPolicyHex", proposedPolicy);
        put(se01, "authorizationSigningInputHex", authInput);
        put(se01, "authorizationSignatureHex", authSig);
        put(se01, "authorizationProofHex", authProof.encoded());
        put(se01, "controllerPopSigningInputHex", popInput);
        put(se01, "controllerPopSignatureHex", popSig);
        put(se01, "controllerProofHex", popProof.encoded());
        put(se01, "signedOperationHex", signed);
        se01.put("sequence", 2);
        se01.put("operationType", 2);
        vectors.add(se01);

        // SE02: mutate identity while retaining SE01 authorization signature.
        byte[] otherIdentity = Arrays.copyOf(TestKeys.IDENTITY,
                TestKeys.IDENTITY.length);
        otherIdentity[31] ^= 1;
        byte[] se02op = rawOi010RotateOperation(
                otherIdentity, 2, v02.stateHash(), proposedPolicy);
        vectors.add(signatureMutation(
                "SE02", "Identity mutation invalidates authorization",
                "INVALID_SIGNATURE", se02op, authSig,
                OpenIdentityCbor.operationSigningInput(se02op)));

        // SE03: mutate sequence.
        byte[] se03op = rawOi010RotateOperation(
                TestKeys.IDENTITY, 3, v02.stateHash(), proposedPolicy);
        vectors.add(signatureMutation(
                "SE03", "Sequence mutation invalidates authorization",
                "INVALID_SIGNATURE", se03op, authSig,
                OpenIdentityCbor.operationSigningInput(se03op)));

        // SE04: mutate predecessor hash.
        byte[] otherHash = Arrays.copyOf(v02.stateHash(),
                v02.stateHash().length);
        otherHash[otherHash.length - 1] ^= 1;
        byte[] se04op = rawOi010RotateOperation(
                TestKeys.IDENTITY, 2, otherHash, proposedPolicy);
        vectors.add(signatureMutation(
                "SE04", "previousStateHash mutation invalidates authorization",
                "INVALID_SIGNATURE", se04op, authSig,
                OpenIdentityCbor.operationSigningInput(se04op)));

        // SE05: mutate payload by installing a different valid policy.
        var otherProposedMethod = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID_C,
                OpenIdentityCbor.ed25519CoseKey(recovery.publicKey()));
        byte[] otherPolicy =
                OpenIdentityCbor.singlePolicy(otherProposedMethod);
        byte[] se05op = rawOi010RotateOperation(
                TestKeys.IDENTITY, 2, v02.stateHash(), otherPolicy);
        Map<String,Object> se05 = signatureMutation(
                "SE05", "Payload mutation invalidates authorization",
                "INVALID_SIGNATURE", se05op, authSig,
                OpenIdentityCbor.operationSigningInput(se05op));
        put(se05, "mutatedControllerPolicyHex", otherPolicy);
        vectors.add(se05);

        // SE06: an ordinary authorization signature cannot satisfy PoP.
        byte[] requiredPopInput =
                OpenIdentityCbor.controllerProofSigningInput(
                        operation, TestKeys.ED25519_METHOD_ID);
        Map<String,Object> se06 = signatureEnvelopeVector(
                "SE06",
                "Ordinary authorization substituted as controller PoP",
                "REJECT", operation);
        se06.put("expectedError", "INVALID_PROOF_OF_POSSESSION");
        put(se06, "substitutedSignatureHex", authSig);
        put(se06, "signatureWasCreatedOverHex", authInput);
        put(se06, "requiredSigningInputHex", requiredPopInput);
        se06.put("substitutionFrom", "OpenIdentity Operation");
        se06.put("substitutionTo", "OpenIdentity Controller Proof");
        vectors.add(se06);

        // SE07: a controller-PoP signature cannot satisfy ordinary auth.
        byte[] controllerAsPopInput =
                OpenIdentityCbor.controllerProofSigningInput(
                        operation, TestKeys.ED25519_METHOD_ID);
        byte[] controllerAsPopSig = controller.sign(controllerAsPopInput);
        Map<String,Object> se07 = signatureEnvelopeVector(
                "SE07",
                "Controller PoP substituted as ordinary authorization",
                "REJECT", operation);
        se07.put("expectedError", "INVALID_SIGNATURE");
        put(se07, "substitutedSignatureHex", controllerAsPopSig);
        put(se07, "signatureWasCreatedOverHex", controllerAsPopInput);
        put(se07, "requiredSigningInputHex", authInput);
        se07.put("substitutionFrom", "OpenIdentity Controller Proof");
        se07.put("substitutionTo", "OpenIdentity Operation");
        vectors.add(se07);

        // SE08: a recovery-domain signature cannot satisfy ordinary auth.
        byte[] recoveryAsAuthInput =
                OpenIdentityCbor.recoveryProofSigningInput(
                        operation, TestKeys.ED25519_METHOD_ID);
        byte[] recoveryAsAuthSig = controller.sign(recoveryAsAuthInput);
        Map<String,Object> se08 = signatureEnvelopeVector(
                "SE08",
                "Recovery authorization substituted as ordinary authorization",
                "REJECT", operation);
        se08.put("expectedError", "INVALID_SIGNATURE");
        put(se08, "substitutedSignatureHex", recoveryAsAuthSig);
        put(se08, "signatureWasCreatedOverHex", recoveryAsAuthInput);
        put(se08, "requiredSigningInputHex", authInput);
        se08.put("substitutionFrom", "OpenIdentity Recovery");
        se08.put("substitutionTo", "OpenIdentity Operation");
        vectors.add(se08);

        // SE09: same operation/domain but signingStructureVersion=2.
        byte[] wrongVersionInput = rawOperationSigningInput(operation, 2);
        Map<String,Object> se09 = signatureEnvelopeVector(
                "SE09",
                "Signing-structure version mutation invalidates authorization",
                "REJECT", operation);
        se09.put("expectedError", "INVALID_SIGNATURE");
        put(se09, "authorizationSignatureHex", authSig);
        put(se09, "signatureWasCreatedOverHex", authInput);
        put(se09, "mutatedSigningInputHex", wrongVersionInput);
        se09.put("originalSigningStructureVersion", 1);
        se09.put("mutatedSigningStructureVersion", 2);
        vectors.add(se09);

        // SE10: mutate operationType from ROTATE_CONTROLLER(2) to
        // DEACTIVATE(4), retaining the original authorization signature.
        byte[] se10op = rawOperationWithPayload(
                4, TestKeys.IDENTITY, 2, v02.stateHash(),
                rawEmptyMap());
        vectors.add(signatureMutation(
                "SE10", "Operation type mutation invalidates authorization",
                "INVALID_SIGNATURE", se10op, authSig,
                OpenIdentityCbor.operationSigningInput(se10op)));

        // Generator-side cryptographic assertions for all substitution cases.
        if (controller.verify(
                OpenIdentityCbor.operationSigningInput(se02op), authSig))
            throw new IllegalStateException("SE02 unexpectedly verified");
        if (controller.verify(
                OpenIdentityCbor.operationSigningInput(se03op), authSig))
            throw new IllegalStateException("SE03 unexpectedly verified");
        if (controller.verify(
                OpenIdentityCbor.operationSigningInput(se04op), authSig))
            throw new IllegalStateException("SE04 unexpectedly verified");
        if (controller.verify(
                OpenIdentityCbor.operationSigningInput(se05op), authSig))
            throw new IllegalStateException("SE05 unexpectedly verified");
        if (controller.verify(requiredPopInput, authSig))
            throw new IllegalStateException("SE06 unexpectedly verified");
        if (controller.verify(authInput, controllerAsPopSig))
            throw new IllegalStateException("SE07 unexpectedly verified");
        if (controller.verify(authInput, recoveryAsAuthSig))
            throw new IllegalStateException("SE08 unexpectedly verified");
        if (controller.verify(wrongVersionInput, authSig))
            throw new IllegalStateException("SE09 unexpectedly verified");
        if (controller.verify(
                OpenIdentityCbor.operationSigningInput(se10op), authSig))
            throw new IllegalStateException("SE10 unexpectedly verified");

        List<String> ids = vectors.stream()
                .map(v -> (String)v.get("id")).toList();
        List<String> expected = java.util.stream.IntStream.rangeClosed(1,10)
                .mapToObj(i -> String.format("SE%02d", i)).toList();
        if (!ids.equals(expected))
            throw new IllegalStateException(
                    "Unexpected signature-envelope vector IDs: " + ids);

        Map<String,Object> doc = new LinkedHashMap<>();
        doc.put("specification", "OpenIdentity Signature Envelope");
        doc.put("version", "0.1");
        doc.put("wireProtocolVersion", 1);
        doc.put("signingStructureVersion", 1);
        doc.put("ordinaryAuthorizationDomain", "OpenIdentity Operation");
        doc.put("controllerProofDomain", "OpenIdentity Controller Proof");
        doc.put("recoveryDomain", "OpenIdentity Recovery");
        doc.put("vectors", vectors);
        writeJson("signature-envelope-se01-se10-java.json", doc);

        for (int i=1;i<=10;i++)
            success(String.format("SE%02d generated", i));
        success("SE01-SE10 generated");
        success("signature-envelope-se01-se10-java.json");
        blankLine();
    }

    private static Map<String,Object> signatureEnvelopeVector(
            String id, String description, String expectedResult,
            byte[] operation) {
        Map<String,Object> v = new LinkedHashMap<>();
        v.put("id", id);
        v.put("description", description);
        v.put("expectedResult", expectedResult);
        put(v, "operationBytesHex", operation);
        return v;
    }

    private static Map<String,Object> signatureMutation(
            String id, String description, String expectedError,
            byte[] operation, byte[] originalSignature,
            byte[] mutatedSigningInput) {
        Map<String,Object> v = signatureEnvelopeVector(
                id, description, "REJECT", operation);
        v.put("expectedError", expectedError);
        put(v, "originalAuthorizationSignatureHex", originalSignature);
        put(v, "mutatedSigningInputHex", mutatedSigningInput);
        return v;
    }

    private static byte[] rawOi010RotateOperation(
            byte[] identity, long sequence, byte[] previousStateHash,
            byte[] controllerPolicy) {
        var p = new DeterministicCborWriter();
        p.writeMapHeader(1);
        p.writeUnsigned(1);
        p.writeEncoded(controllerPolicy);
        return rawOperationWithPayload(
                2, identity, sequence, previousStateHash, p.toByteArray());
    }

    private static byte[] rawOperationWithPayload(
            int operationType, byte[] identity, long sequence,
            byte[] previousStateHash, byte[] payload) {
        var c = new DeterministicCborWriter();
        c.writeMapHeader(6);
        c.writeUnsigned(1); c.writeUnsigned(1);
        c.writeUnsigned(2); c.writeUnsigned(operationType);
        c.writeUnsigned(3); c.writeByteString(identity);
        c.writeUnsigned(4); c.writeUnsigned(sequence);
        c.writeUnsigned(5);
        if (previousStateHash == null) c.writeNull();
        else c.writeByteString(previousStateHash);
        c.writeUnsigned(6); c.writeEncoded(payload);
        return c.toByteArray();
    }

    private static byte[] rawOperationSigningInput(
            byte[] operation, int signingStructureVersion) {
        var c = new DeterministicCborWriter();
        c.writeArrayHeader(3);
        c.writeTextString("OpenIdentity Operation");
        c.writeUnsigned(signingStructureVersion);
        c.writeByteString(operation);
        return c.toByteArray();
    }

    private static byte[] rawEmptyMap() {
        var c = new DeterministicCborWriter();
        c.writeMapHeader(0);
        return c.toByteArray();
    }



    /**
     * Consolidates independently verified OI-010 SE01-SE10 into the
     * normative signature-envelope-v0.1.json artifact and hashes the exact
     * JSON bytes written to disk.
     */
    @SuppressWarnings("unchecked")
    private static void generateNormativeSignatureEnvelopeFile() {
        section("NORMATIVE", "Consolidating OI-010 signature-envelope vectors");
        try {
            Path root = Path.of("..", "..").toAbsolutePath().normalize();
            Path gen = root.resolve("test-vectors").resolve("generated");
            Path tv = root.resolve("test-vectors");
            ObjectMapper mapper = new ObjectMapper();

            Path generatedFile =
                    gen.resolve("signature-envelope-se01-se10-java.json");
            Map<String,Object> generated = mapper.readValue(
                    generatedFile.toFile(), Map.class);

            if (!"OpenIdentity Signature Envelope".equals(
                    generated.get("specification"))
                    || !"0.1".equals(generated.get("version"))
                    || !Integer.valueOf(1).equals(
                    generated.get("wireProtocolVersion"))
                    || !Integer.valueOf(1).equals(
                    generated.get("signingStructureVersion"))
                    || !"OpenIdentity Operation".equals(
                    generated.get("ordinaryAuthorizationDomain"))
                    || !"OpenIdentity Controller Proof".equals(
                    generated.get("controllerProofDomain"))
                    || !"OpenIdentity Recovery".equals(
                    generated.get("recoveryDomain"))) {
                throw new IllegalStateException(
                        "Generated OI-010 suite metadata is invalid");
            }

            Object raw = generated.get("vectors");
            if (!(raw instanceof List<?>)) {
                throw new IllegalStateException(
                        "Generated OI-010 suite missing vectors array");
            }
            List<Map<String,Object>> vectors =
                    (List<Map<String,Object>>) raw;

            if (vectors.size() != 10) {
                throw new IllegalStateException(
                        "OI-010 requires exactly 10 vectors");
            }

            List<String> expectedIds =
                    java.util.stream.IntStream.rangeClosed(1,10)
                            .mapToObj(i -> String.format("SE%02d", i))
                            .toList();
            List<String> actualIds = vectors.stream()
                    .map(v -> (String)v.get("id"))
                    .toList();
            if (!actualIds.equals(expectedIds)) {
                throw new IllegalStateException(
                        "Unexpected OI-010 vector IDs: " + actualIds);
            }

            for (int i = 0; i < vectors.size(); i++) {
                Map<String,Object> v = vectors.get(i);
                String id = expectedIds.get(i);
                String expectedResult = i == 0 ? "ACCEPT" : "REJECT";
                if (!expectedResult.equals(v.get("expectedResult"))) {
                    throw new IllegalStateException(
                            id + " expectedResult must be "
                                    + expectedResult);
                }
                if (i > 0) {
                    Object err = v.get("expectedError");
                    if (!(err instanceof String)
                            || ((String)err).isBlank()) {
                        throw new IllegalStateException(
                                id + " missing expectedError");
                    }
                }
            }

            Map<String,Object> domains = new LinkedHashMap<>();
            domains.put(
                    "ordinaryAuthorization",
                    "OpenIdentity Operation");
            domains.put(
                    "controllerProofOfPossession",
                    "OpenIdentity Controller Proof");
            domains.put(
                    "recoveryAuthorization",
                    "OpenIdentity Recovery");

            Map<String,Object> coverage = new LinkedHashMap<>();
            coverage.put("operationFieldsCovered", List.of(
                    "protocolVersion",
                    "operationType",
                    "identity",
                    "sequence",
                    "previousStateHash",
                    "payload"));
            coverage.put(
                    "proofCollectionsExcludedFromOperationBytes",
                    true);
            coverage.put(
                    "signingStructureVersionIndependentOfProtocolVersion",
                    true);

            Map<String,Object> normative = new LinkedHashMap<>();
            normative.put(
                    "specification",
                    "OpenIdentity Signature Envelope");
            normative.put("version", "0.1");
            normative.put("wireProtocolVersion", 1);
            normative.put("signingStructureVersion", 1);
            normative.put("domains", domains);
            normative.put("coverage", coverage);
            normative.put("vectors", vectors);

            ObjectMapper output = new ObjectMapper()
                    .enable(SerializationFeature.INDENT_OUTPUT);

            Path jsonFile =
                    tv.resolve("signature-envelope-v0.1.json");
            output.writeValue(jsonFile.toFile(), normative);

            byte[] jsonBytes = Files.readAllBytes(jsonFile);
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(jsonBytes);
            String sha256 = Hex.encode(digest);

            Path checksumFile =
                    tv.resolve("signature-envelope-v0.1.json.sha256");
            Files.writeString(
                    checksumFile,
                    sha256 + "  signature-envelope-v0.1.json\n");

            success("SE01-SE10 consolidated");
            success("signature-envelope-v0.1.json");
            success("SHA-256 " + sha256);
            success("signature-envelope-v0.1.json.sha256");
            blankLine();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Unable to generate normative OI-010 signature-envelope vector file",
                    e);
        }
    }



    /**
     * OI-011 SH01-SH10 StateHash conformance/security vectors.
     */
    private static void generateStateHashVectors(
            HybridCreateResult v02,
            AssertionStateResult a04) {
        section("STATE HASH", "SH01-SH10");

        var edA = new Ed25519Support(TestKeys.ED25519_SEED);
        var mlA = new MlDsa65Support(TestKeys.ML_DSA_SEED);
        var edB = new Ed25519Support(TestKeys.ED25519_SEED_B);
        var mlB = new MlDsa65Support(TestKeys.ML_DSA_SEED_B);

        var edMethodA = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID,
                OpenIdentityCbor.ed25519CoseKey(edA.publicKey()));
        var mlMethodA = OpenIdentityCbor.verificationMethod(
                TestKeys.ML_DSA_METHOD_ID,
                OpenIdentityCbor.mlDsa65CoseKey(mlA.publicKey()));
        byte[] policyA = OpenIdentityCbor.thresholdPolicy(
                2, List.of(edMethodA, mlMethodA));

        var edMethodB = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID_B,
                OpenIdentityCbor.ed25519CoseKey(edB.publicKey()));
        var mlMethodB = OpenIdentityCbor.verificationMethod(
                TestKeys.ML_DSA_METHOD_ID_B,
                OpenIdentityCbor.mlDsa65CoseKey(mlB.publicKey()));
        byte[] policyB = OpenIdentityCbor.thresholdPolicy(
                2, List.of(edMethodB, mlMethodB));

        byte[] recoveryPolicy = OpenIdentityCbor.recoverySinglePolicy(
                edMethodB);
        byte[] recoveryCommitment =
                OpenIdentityCbor.recoveryCommitment(recoveryPolicy);

        List<Map<String,Object>> vectors = new ArrayList<>();

        // SH01 — canonical v1 baseline.
        byte[] sh01State = OpenIdentityCbor.identityState(
                1, TestKeys.IDENTITY, 1, 1,
                policyA, null, null);
        byte[] sh01Hash = StateHash.sha256Multihash(sh01State);
        vectors.add(stateHashVector(
                "SH01",
                "IdentityState v1 produces expected SHA2-256 Multihash StateHash",
                sh01State, sh01Hash));

        // SH02 — canonical v2 baseline with AssertionPolicy.
        byte[] sh02State = OpenIdentityCbor.identityState(
                2, TestKeys.IDENTITY, 5, 1,
                policyA, null, a04.assertionPolicy());
        byte[] sh02Hash = StateHash.sha256Multihash(sh02State);
        Map<String,Object> sh02 = stateHashVector(
                "SH02",
                "IdentityState v2 with AssertionPolicy produces expected StateHash",
                sh02State, sh02Hash);
        put(sh02, "assertionPolicyHex", a04.assertionPolicy());
        vectors.add(sh02);

        // SH03 — sequence mutation.
        byte[] sh03State = OpenIdentityCbor.identityState(
                1, TestKeys.IDENTITY, 2, 1,
                policyA, null, null);
        Map<String,Object> sh03 = stateHashMutation(
                "SH03", "Sequence mutation changes StateHash",
                sh01State, sh01Hash, sh03State);
        sh03.put("baselineSequence", 1);
        sh03.put("mutatedSequence", 2);
        vectors.add(sh03);

        // SH04 — status mutation.
        byte[] sh04State = OpenIdentityCbor.identityState(
                1, TestKeys.IDENTITY, 1, 2,
                policyA, null, null);
        Map<String,Object> sh04 = stateHashMutation(
                "SH04", "Status mutation ACTIVE to DEACTIVATED changes StateHash",
                sh01State, sh01Hash, sh04State);
        sh04.put("baselineStatus", "ACTIVE");
        sh04.put("mutatedStatus", "DEACTIVATED");
        vectors.add(sh04);

        // SH05 — ControllerPolicy mutation.
        byte[] sh05State = OpenIdentityCbor.identityState(
                1, TestKeys.IDENTITY, 1, 1,
                policyB, null, null);
        Map<String,Object> sh05 = stateHashMutation(
                "SH05", "ControllerPolicy mutation changes StateHash",
                sh01State, sh01Hash, sh05State);
        put(sh05, "baselineControllerPolicyHex", policyA);
        put(sh05, "mutatedControllerPolicyHex", policyB);
        vectors.add(sh05);

        // SH06 — recoveryCommitment mutation/presence.
        byte[] sh06State = OpenIdentityCbor.identityState(
                1, TestKeys.IDENTITY, 1, 1,
                policyA, recoveryCommitment, null);
        Map<String,Object> sh06 = stateHashMutation(
                "SH06", "recoveryCommitment mutation changes StateHash",
                sh01State, sh01Hash, sh06State);
        put(sh06, "recoveryPolicyHex", recoveryPolicy);
        put(sh06, "mutatedRecoveryCommitmentHex", recoveryCommitment);
        vectors.add(sh06);

        // SH07 — AssertionPolicy mutation within v2.
        var assertionC = new Ed25519Support(TestKeys.ED25519_SEED_C);
        var assertionMethodC = OpenIdentityCbor.verificationMethod(
                TestKeys.ED25519_METHOD_ID_C,
                OpenIdentityCbor.ed25519CoseKey(assertionC.publicKey()));
        byte[] assertionPolicyC =
                OpenIdentityCbor.singlePolicy(assertionMethodC);
        byte[] sh07State = OpenIdentityCbor.identityState(
                2, TestKeys.IDENTITY, 5, 1,
                policyA, null, assertionPolicyC);
        Map<String,Object> sh07 = stateHashMutation(
                "SH07", "AssertionPolicy mutation changes StateHash",
                sh02State, sh02Hash, sh07State);
        put(sh07, "baselineAssertionPolicyHex", a04.assertionPolicy());
        put(sh07, "mutatedAssertionPolicyHex", assertionPolicyC);
        vectors.add(sh07);

        // SH08 — reversed method construction canonicalizes identically.
        byte[] reversedPolicy = OpenIdentityCbor.thresholdPolicy(
                2, List.of(mlMethodA, edMethodA));
        byte[] sh08State = OpenIdentityCbor.identityState(
                1, TestKeys.IDENTITY, 1, 1,
                reversedPolicy, null, null);
        byte[] sh08Hash = StateHash.sha256Multihash(sh08State);
        if (!Arrays.equals(policyA, reversedPolicy)
                || !Arrays.equals(sh01State, sh08State)
                || !Arrays.equals(sh01Hash, sh08Hash)) {
            throw new IllegalStateException(
                    "SH08 canonicalization invariance failed");
        }
        Map<String,Object> sh08 = stateHashVector(
                "SH08",
                "Reversed VerificationMethod input order produces identical canonical StateBytes and StateHash",
                sh08State, sh08Hash);
        put(sh08, "baselineStateBytesHex", sh01State);
        put(sh08, "baselineStateHashHex", sh01Hash);
        sh08.put("inputMethodOrder",
                List.of("ML-DSA-65", "Ed25519"));
        sh08.put("canonicalStateBytesMatch", true);
        sh08.put("canonicalStateHashMatch", true);
        vectors.add(sh08);

        // SH09 — raw SHA-256 digest is not the 34-byte StateHash.
        byte[] rawDigest;
        try {
            rawDigest = MessageDigest.getInstance("SHA-256")
                    .digest(sh01State);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        if (rawDigest.length != 32
                || Arrays.equals(rawDigest, sh01Hash)) {
            throw new IllegalStateException(
                    "SH09 raw digest distinction failed");
        }
        Map<String,Object> sh09 = stateHashVector(
                "SH09",
                "Raw SHA-256 digest alone is not StateHash",
                sh01State, sh01Hash);
        put(sh09, "rawSha256DigestHex", rawDigest);
        sh09.put("rawDigestLength", rawDigest.length);
        sh09.put("stateHashLength", sh01Hash.length);
        sh09.put("rawDigestIsStateHash", false);
        vectors.add(sh09);

        // SH10 — hashing a non-StateBytes representation is not authoritative.
        // Use the exact canonical OperationBytes from V02 as the alternate
        // binary representation: valid protocol bytes, but not IdentityState.
        byte[] alternateBytes = v02.operation();
        byte[] alternateHash = StateHash.sha256Multihash(alternateBytes);
        if (Arrays.equals(alternateHash, sh01Hash)) {
            throw new IllegalStateException(
                    "SH10 alternate representation unexpectedly matched");
        }
        Map<String,Object> sh10 = stateHashVector(
                "SH10",
                "Hash of non-StateBytes representation is not authoritative StateHash",
                sh01State, sh01Hash);
        sh10.put("alternateRepresentation", "OperationBytes");
        put(sh10, "alternateBytesHex", alternateBytes);
        put(sh10, "alternateMultihashHex", alternateHash);
        sh10.put("alternateHashIsAuthoritativeStateHash", false);
        vectors.add(sh10);

        for (Map<String,Object> v : vectors) {
            byte[] state = Hex.decode((String)v.get("stateBytesHex"));
            byte[] hash = Hex.decode((String)v.get("stateHashHex"));
            if (hash.length != 34
                    || hash[0] != 0x12
                    || hash[1] != 0x20
                    || !Arrays.equals(
                    StateHash.sha256Multihash(state), hash)) {
                throw new IllegalStateException(
                        v.get("id") + " StateHash self-check failed");
            }
        }

        List<String> ids = vectors.stream()
                .map(v -> (String)v.get("id")).toList();
        List<String> expected =
                java.util.stream.IntStream.rangeClosed(1,10)
                        .mapToObj(i -> String.format("SH%02d", i))
                        .toList();
        if (!ids.equals(expected))
            throw new IllegalStateException(
                    "Unexpected StateHash vector IDs: " + ids);

        Map<String,Object> profile = new LinkedHashMap<>();
        profile.put("hashAlgorithm", "SHA-256");
        profile.put("multihashCode", 18);
        profile.put("digestLength", 32);
        profile.put("stateHashLength", 34);
        profile.put(
                "formula",
                "0x12 || 0x20 || SHA-256(StateBytes)");

        Map<String,Object> doc = new LinkedHashMap<>();
        doc.put("specification", "OpenIdentity StateHash");
        doc.put("version", "0.1");
        doc.put("identityStateVersions", List.of(1,2));
        doc.put("profile", profile);
        doc.put("vectors", vectors);
        writeJson("state-hash-sh01-sh10-java.json", doc);

        for (int i=1;i<=10;i++)
            success(String.format("SH%02d generated", i));
        success("SH01-SH10 generated");
        success("state-hash-sh01-sh10-java.json");
        blankLine();
    }

    private static Map<String,Object> stateHashVector(
            String id, String description,
            byte[] stateBytes, byte[] stateHash) {
        Map<String,Object> v = new LinkedHashMap<>();
        v.put("id", id);
        v.put("description", description);
        put(v, "stateBytesHex", stateBytes);
        put(v, "stateHashHex", stateHash);
        v.put("stateHashLength", stateHash.length);
        return v;
    }

    private static Map<String,Object> stateHashMutation(
            String id, String description,
            byte[] baselineState, byte[] baselineHash,
            byte[] mutatedState) {
        byte[] mutatedHash = StateHash.sha256Multihash(mutatedState);
        if (Arrays.equals(baselineState, mutatedState)
                || Arrays.equals(baselineHash, mutatedHash)) {
            throw new IllegalStateException(
                    id + " mutation did not change state/hash");
        }
        Map<String,Object> v = stateHashVector(
                id, description, mutatedState, mutatedHash);
        put(v, "baselineStateBytesHex", baselineState);
        put(v, "baselineStateHashHex", baselineHash);
        v.put("stateBytesChanged", true);
        v.put("stateHashChanged", true);
        return v;
    }



    /**
     * Consolidates independently verified OI-011 SH01-SH10 into the
     * normative state-hash-v0.1.json artifact and hashes the exact JSON
     * bytes written to disk.
     */
    @SuppressWarnings("unchecked")
    private static void generateNormativeStateHashFile() {
        section("NORMATIVE", "Consolidating OI-011 StateHash vectors");
        try {
            Path root = Path.of("..", "..").toAbsolutePath().normalize();
            Path gen = root.resolve("test-vectors").resolve("generated");
            Path tv = root.resolve("test-vectors");
            ObjectMapper mapper = new ObjectMapper();

            Path generatedFile =
                    gen.resolve("state-hash-sh01-sh10-java.json");
            Map<String,Object> generated = mapper.readValue(
                    generatedFile.toFile(), Map.class);

            if (!"OpenIdentity StateHash".equals(
                    generated.get("specification"))
                    || !"0.1".equals(generated.get("version"))) {
                throw new IllegalStateException(
                        "Generated OI-011 suite metadata is invalid");
            }

            Object versionsRaw = generated.get("identityStateVersions");
            if (!(versionsRaw instanceof List<?> versions)
                    || !versions.equals(List.of(1, 2))) {
                throw new IllegalStateException(
                        "OI-011 IdentityState versions must be [1, 2]");
            }

            Object profileRaw = generated.get("profile");
            if (!(profileRaw instanceof Map<?,?>)) {
                throw new IllegalStateException(
                        "OI-011 suite missing profile");
            }
            Map<String,Object> profile =
                    (Map<String,Object>) profileRaw;

            if (!"SHA-256".equals(profile.get("hashAlgorithm"))
                    || !Integer.valueOf(18).equals(
                    profile.get("multihashCode"))
                    || !Integer.valueOf(32).equals(
                    profile.get("digestLength"))
                    || !Integer.valueOf(34).equals(
                    profile.get("stateHashLength"))
                    || !"0x12 || 0x20 || SHA-256(StateBytes)".equals(
                    profile.get("formula"))) {
                throw new IllegalStateException(
                        "OI-011 StateHash profile is invalid");
            }

            Object raw = generated.get("vectors");
            if (!(raw instanceof List<?>)) {
                throw new IllegalStateException(
                        "Generated OI-011 suite missing vectors");
            }
            List<Map<String,Object>> vectors =
                    (List<Map<String,Object>>) raw;

            if (vectors.size() != 10) {
                throw new IllegalStateException(
                        "OI-011 requires exactly 10 vectors");
            }

            List<String> expectedIds =
                    java.util.stream.IntStream.rangeClosed(1,10)
                            .mapToObj(i -> String.format("SH%02d", i))
                            .toList();
            List<String> actualIds = vectors.stream()
                    .map(v -> (String)v.get("id"))
                    .toList();
            if (!actualIds.equals(expectedIds)) {
                throw new IllegalStateException(
                        "Unexpected OI-011 vector IDs: " + actualIds);
            }

            // Every vector carries canonical StateBytes and the exact v0.1
            // 34-byte SHA2-256 Multihash over those bytes.
            for (Map<String,Object> v : vectors) {
                String id = (String)v.get("id");
                Object stateHex = v.get("stateBytesHex");
                Object hashHex = v.get("stateHashHex");
                if (!(stateHex instanceof String)
                        || !(hashHex instanceof String)) {
                    throw new IllegalStateException(
                            id + " missing state/hash bytes");
                }

                byte[] state = Hex.decode((String)stateHex);
                byte[] hash = Hex.decode((String)hashHex);
                byte[] expectedHash =
                        StateHash.sha256Multihash(state);

                if (hash.length != 34
                        || hash[0] != 0x12
                        || hash[1] != 0x20
                        || !Arrays.equals(hash, expectedHash)
                        || !Integer.valueOf(34).equals(
                        v.get("stateHashLength"))) {
                    throw new IllegalStateException(
                            id + " has invalid v0.1 StateHash");
                }
            }

            // Security/invariance markers must survive consolidation.
            if (!Boolean.TRUE.equals(
                    vectors.get(7).get("canonicalStateBytesMatch"))
                    || !Boolean.TRUE.equals(
                    vectors.get(7).get("canonicalStateHashMatch"))
                    || !Boolean.FALSE.equals(
                    vectors.get(8).get("rawDigestIsStateHash"))
                    || !Boolean.FALSE.equals(
                    vectors.get(9).get(
                            "alternateHashIsAuthoritativeStateHash"))) {
                throw new IllegalStateException(
                        "OI-011 SH08-SH10 invariants are invalid");
            }

            Map<String,Object> semantics = new LinkedHashMap<>();
            semantics.put("input", "canonical StateBytes");
            semantics.put("completeIdentityStateCommitted", true);
            semantics.put("exactBinaryMultihashComparison", true);
            semantics.put("rawSha256DigestIsNotStateHash", true);
            semantics.put("nonStateBytesHashIsNotAuthoritative", true);

            Map<String,Object> normative = new LinkedHashMap<>();
            normative.put("specification", "OpenIdentity StateHash");
            normative.put("version", "0.1");
            normative.put("identityStateVersions", List.of(1, 2));
            normative.put("profile", profile);
            normative.put("semantics", semantics);
            normative.put("vectors", vectors);

            ObjectMapper output = new ObjectMapper()
                    .enable(SerializationFeature.INDENT_OUTPUT);

            Path jsonFile = tv.resolve("state-hash-v0.1.json");
            output.writeValue(jsonFile.toFile(), normative);

            byte[] jsonBytes = Files.readAllBytes(jsonFile);
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(jsonBytes);
            String sha256 = Hex.encode(digest);

            Path checksumFile =
                    tv.resolve("state-hash-v0.1.json.sha256");
            Files.writeString(
                    checksumFile,
                    sha256 + "  state-hash-v0.1.json\n");

            success("SH01-SH10 consolidated");
            success("state-hash-v0.1.json");
            success("SHA-256 " + sha256);
            success("state-hash-v0.1.json.sha256");
            blankLine();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Unable to generate normative OI-011 StateHash vector file",
                    e);
        }
    }


    private static void generateAllInvalidVectors(HybridCreateResult v02) {
        generateInvalidVectors(v02);
        generateInvalidVectorsI06ToI20(v02);
        try {
            Path root = Path.of("..", "..").toAbsolutePath().normalize();
            Path dir = root.resolve("test-vectors").resolve("generated");
            ObjectMapper mapper = new ObjectMapper();
            Map<?, ?> a = mapper.readValue(dir.resolve("crypto-invalid-java.json").toFile(), Map.class);
            Map<?, ?> b = mapper.readValue(dir.resolve("crypto-invalid-i06-i20-java.json").toFile(), Map.class);
            List<Object> all = new java.util.ArrayList<>();
            all.addAll((List<?>) a.get("vectors"));
            all.addAll((List<?>) b.get("vectors"));
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("specification", "OpenIdentity Cryptographic Agility");
            d.put("version", "0.1");
            d.put("type", "invalid-conformance-vectors");
            d.put("vectors", all);
            writeJson("crypto-invalid-java.json", d);
            Files.deleteIfExists(dir.resolve("crypto-invalid-i06-i20-java.json"));
            success("20 invalid vectors consolidated");
            success("crypto-invalid-java.json");
            blankLine();
        } catch (IOException e) {
            throw new IllegalStateException("Unable to consolidate invalid vectors", e);
        }
    }

    private static void generateInvalidVectors(HybridCreateResult v02) {
        section("INVALID", "I01-I05");
        var ed = new Ed25519Support(TestKeys.ED25519_SEED);
        var ml = new MlDsa65Support(TestKeys.ML_DSA_SEED);
        byte[] ec = OpenIdentityCbor.ed25519CoseKey(ed.publicKey());
        byte[] mc = OpenIdentityCbor.mlDsa65CoseKey(ml.publicKey());
        var em = OpenIdentityCbor.verificationMethod(TestKeys.ED25519_METHOD_ID, ec);
        var mm = OpenIdentityCbor.verificationMethod(TestKeys.ML_DSA_METHOD_ID, mc);
        List<Map<String, Object>> vs = new java.util.ArrayList<>();

        byte[] i01 = rawCreateOperation(TestKeys.IDENTITY, 2, null, v02.controllerPolicy());
        vs.add(invalidVector("I01", "CREATE sequence is 2 instead of 1", "INVALID_SEQUENCE", i01));

        byte[] i02 = rawCreateOperation(TestKeys.IDENTITY, 1, v02.stateHash(), v02.controllerPolicy());
        vs.add(invalidVector("I02", "CREATE contains a previousStateHash", "INVALID_PREVIOUS_STATE_HASH", i02));

        byte[] p03 = rawThresholdPolicy(0, List.of(em, mm));
        vs.add(invalidVector("I03", "Controller threshold is zero", "INVALID_CONTROLLER_THRESHOLD",
                rawCreateOperation(TestKeys.IDENTITY, 1, null, p03)));

        byte[] p04 = rawThresholdPolicy(3, List.of(em, mm));
        vs.add(invalidVector("I04", "Controller threshold exceeds VerificationMethod count", "INVALID_CONTROLLER_THRESHOLD",
                rawCreateOperation(TestKeys.IDENTITY, 1, null, p04)));

        var dup = OpenIdentityCbor.verificationMethod(TestKeys.ED25519_METHOD_ID, mc);
        byte[] p05 = rawThresholdPolicy(2, List.of(em, dup));
        vs.add(invalidVector("I05", "Duplicate Verification Method ID", "DUPLICATE_VERIFICATION_METHOD",
                rawCreateOperation(TestKeys.IDENTITY, 1, null, p05)));

        Map<String, Object> d = new LinkedHashMap<>();
        d.put("specification", "OpenIdentity Cryptographic Agility");
        d.put("version", "0.1");
        d.put("type", "invalid-conformance-vectors");
        d.put("vectors", vs);
        writeJson("crypto-invalid-java.json", d);
        success("I01-I05 generated");
        blankLine();
    }

    private static byte[] rawCreateOperation(byte[] identity, long sequence, byte[] previousStateHash, byte[] policy) {
        var payload = new DeterministicCborWriter();
        payload.writeMapHeader(1);
        payload.writeUnsigned(1);
        payload.writeEncoded(policy);
        var c = new DeterministicCborWriter();
        c.writeMapHeader(6);
        c.writeUnsigned(1);
        c.writeUnsigned(1);
        c.writeUnsigned(2);
        c.writeUnsigned(1);
        c.writeUnsigned(3);
        c.writeByteString(identity);
        c.writeUnsigned(4);
        c.writeUnsigned(sequence);
        c.writeUnsigned(5);
        if (previousStateHash == null) c.writeNull();
        else c.writeByteString(previousStateHash);
        c.writeUnsigned(6);
        c.writeEncoded(payload.toByteArray());
        return c.toByteArray();
    }

    private static byte[] rawThresholdPolicy(int threshold, List<OpenIdentityCbor.EncodedVerificationMethod> methods) {
        var sorted = new java.util.ArrayList<>(methods);
        sorted.sort((a, b) -> compareUnsignedBytes(a.id(), b.id()));
        var c = new DeterministicCborWriter();
        c.writeMapHeader(3);
        c.writeUnsigned(1);
        c.writeUnsigned(2);
        c.writeUnsigned(2);
        c.writeUnsigned(threshold);
        c.writeUnsigned(3);
        c.writeArrayHeader(sorted.size());
        for (var m : sorted) c.writeEncoded(m.encoded());
        return c.toByteArray();
    }

    private static int compareUnsignedBytes(byte[] a, byte[] b) {
        for (int i = 0; i < Math.min(a.length, b.length); i++) {
            int x = Byte.toUnsignedInt(a[i]), y = Byte.toUnsignedInt(b[i]);
            if (x != y) return Integer.compare(x, y);
        }
        return Integer.compare(a.length, b.length);
    }

    private static Map<String, Object> invalidVector(String id, String description, String expectedError, byte[] operation) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", id);
        v.put("description", description);
        v.put("expectedError", expectedError);
        v.put("operationBytesHex", Hex.encode(operation));
        return v;
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

        List<Map<String, Object>> vs = new java.util.ArrayList<>();
        vs.add(invalidSigned("I06", "Missing Ed25519 authorization proof", "CONTROLLER_THRESHOLD_NOT_SATISFIED",
                createOp, rawSignedOperation(createOp, List.of(mlProof), List.of())));
        vs.add(invalidSigned("I07", "Duplicate authorization proof", "DUPLICATE_PROOF",
                createOp, rawSignedOperation(createOp, List.of(edProof, edProof), List.of())));

        byte[] badEd = oldEd.sign(createInput);
        badEd[0] ^= 1;
        vs.add(invalidSigned("I08", "Corrupted Ed25519 authorization signature", "INVALID_SIGNATURE", createOp,
                rawSignedOperation(createOp, List.of(OpenIdentityCbor.authorizationProof(TestKeys.ED25519_METHOD_ID, badEd), mlProof), List.of())));
        byte[] badMl = oldMl.sign(createInput);
        badMl[0] ^= 1;
        vs.add(invalidSigned("I09", "Corrupted ML-DSA-65 authorization signature", "INVALID_SIGNATURE", createOp,
                rawSignedOperation(createOp, List.of(edProof, OpenIdentityCbor.authorizationProof(TestKeys.ML_DSA_METHOD_ID, badMl)), List.of())));

        byte[] uid = Hex.decode("808182838485868788898a8b8c8d8e8f");
        var up = OpenIdentityCbor.authorizationProof(uid, oldEd.sign(createInput));
        vs.add(invalidSigned("I10", "Unauthorized Verification Method ID", "UNAUTHORIZED_VERIFICATION_METHOD",
                createOp, rawSignedOperation(createOp, List.of(edProof, mlProof, up), List.of())));

        byte[] wrongHash = Arrays.copyOf(v02.stateHash(), 34);
        wrongHash[33] ^= 1;
        vs.add(invalidOperationOnly("I11", "Incorrect previousStateHash", "INVALID_PREVIOUS_STATE_HASH",
                OpenIdentityCbor.rotateControllerOperation(TestKeys.IDENTITY, 2, wrongHash, newPolicy)));
        vs.add(invalidOperationOnly("I12", "ROTATE sequence is not current + 1", "INVALID_SEQUENCE",
                rawRotateOperation(TestKeys.IDENTITY, 3, v02.stateHash(), newPolicy)));

        vs.add(invalidSigned("I13", "New Ed25519 key missing PoP", "MISSING_PROOF_OF_POSSESSION", rotate,
                rawSignedOperation(rotate, List.of(oldEdRot, oldMlRot), List.of(mPop))));
        vs.add(invalidSigned("I14", "New ML-DSA key missing PoP", "MISSING_PROOF_OF_POSSESSION", rotate,
                rawSignedOperation(rotate, List.of(oldEdRot, oldMlRot), List.of(ePop))));

        var wrongDomain = OpenIdentityCbor.controllerProof(TestKeys.ED25519_METHOD_ID_B, newEd.sign(authIn));
        vs.add(invalidSigned("I15", "PoP uses authorization domain", "INVALID_PROOF_OF_POSSESSION", rotate,
                rawSignedOperation(rotate, List.of(oldEdRot, oldMlRot), List.of(wrongDomain, mPop))));
        var wrongBound = OpenIdentityCbor.controllerProof(TestKeys.ML_DSA_METHOD_ID_B, newEd.sign(ePopIn));
        vs.add(invalidSigned("I16", "PoP bound to wrong method ID", "INVALID_PROOF_OF_POSSESSION", rotate,
                rawSignedOperation(rotate, List.of(oldEdRot, oldMlRot), List.of(ePop, wrongBound))));

        var selfE = OpenIdentityCbor.authorizationProof(TestKeys.ED25519_METHOD_ID_B, newEd.sign(authIn));
        var selfM = OpenIdentityCbor.authorizationProof(TestKeys.ML_DSA_METHOD_ID_B, newMl.sign(authIn));
        vs.add(invalidSigned("I17", "New controller self-authorizes rotation", "CONTROLLER_THRESHOLD_NOT_SATISFIED", rotate,
                rawSignedOperation(rotate, List.of(selfE, selfM), List.of(ePop, mPop))));

        var unsupported = OpenIdentityCbor.verificationMethod(Hex.decode("909192939495969798999a9b9c9d9e9f"), rawUnsupportedCoseKey());
        byte[] unsupportedPolicy = rawThresholdPolicy(1, List.of(unsupported));
        vs.add(invalidOperationOnly("I18", "Unsupported algorithm", "UNSUPPORTED_ALGORITHM",
                rawCreateOperation(TestKeys.IDENTITY, 1, null, unsupportedPolicy)));
        vs.add(invalidOperationOnly("I19", "Unknown signed map field", "UNSUPPORTED_PROTOCOL_FEATURE",
                rawCreateWithUnknownField(TestKeys.IDENTITY, oldPolicy)));
        vs.add(invalidOperationOnly("I20", "OI-002 v0.1 reserved RECOVER before OI-007 definition", "UNSUPPORTED_OPERATION",
                rawRecoverOperation(TestKeys.IDENTITY, 2, v02.stateHash())));

        Map<String, Object> d = new LinkedHashMap<>();
        d.put("specification", "OpenIdentity Cryptographic Agility");
        d.put("version", "0.1");
        d.put("type", "invalid-conformance-vectors-i06-i20");
        d.put("vectors", vs);
        writeJson("crypto-invalid-i06-i20-java.json", d);
    }

    private static Map<String, Object> invalidSigned(String id, String desc, String error, byte[] op, byte[] signed) {
        Map<String, Object> v = invalidVector(id, desc, error, op);
        v.put("signedOperationHex", Hex.encode(signed));
        return v;
    }

    private static Map<String, Object> invalidOperationOnly(String id, String desc, String error, byte[] op) {
        return invalidVector(id, desc, error, op);
    }

    private static byte[] rawSignedOperation(byte[] op, List<OpenIdentityCbor.EncodedProof> auth, List<OpenIdentityCbor.EncodedProof> pop) {
        var c = new DeterministicCborWriter();
        c.writeMapHeader(pop.isEmpty() ? 2 : 3);
        c.writeUnsigned(1);
        c.writeEncoded(op);
        c.writeUnsigned(2);
        c.writeArrayHeader(auth.size());
        for (var p : auth) c.writeEncoded(p.encoded());
        if (!pop.isEmpty()) {
            c.writeUnsigned(3);
            c.writeArrayHeader(pop.size());
            for (var p : pop) c.writeEncoded(p.encoded());
        }
        return c.toByteArray();
    }

    private static byte[] rawRotateOperation(byte[] id, long seq, byte[] prev, byte[] policy) {
        var p = new DeterministicCborWriter();
        p.writeMapHeader(1);
        p.writeUnsigned(1);
        p.writeEncoded(policy);
        var c = new DeterministicCborWriter();
        c.writeMapHeader(6);
        c.writeUnsigned(1);
        c.writeUnsigned(1);
        c.writeUnsigned(2);
        c.writeUnsigned(2);
        c.writeUnsigned(3);
        c.writeByteString(id);
        c.writeUnsigned(4);
        c.writeUnsigned(seq);
        c.writeUnsigned(5);
        c.writeByteString(prev);
        c.writeUnsigned(6);
        c.writeEncoded(p.toByteArray());
        return c.toByteArray();
    }

    private static byte[] rawUnsupportedCoseKey() {
        var c = new DeterministicCborWriter();
        c.writeMapHeader(2);
        c.writeUnsigned(1);
        c.writeUnsigned(7);
        c.writeUnsigned(3);
        c.writeSigned(-999);
        return c.toByteArray();
    }

    private static byte[] rawCreateWithUnknownField(byte[] id, byte[] policy) {
        var p = new DeterministicCborWriter();
        p.writeMapHeader(1);
        p.writeUnsigned(1);
        p.writeEncoded(policy);
        var c = new DeterministicCborWriter();
        c.writeMapHeader(7);
        c.writeUnsigned(1);
        c.writeUnsigned(1);
        c.writeUnsigned(2);
        c.writeUnsigned(1);
        c.writeUnsigned(3);
        c.writeByteString(id);
        c.writeUnsigned(4);
        c.writeUnsigned(1);
        c.writeUnsigned(5);
        c.writeNull();
        c.writeUnsigned(6);
        c.writeEncoded(p.toByteArray());
        c.writeUnsigned(99);
        c.writeUnsigned(1);
        return c.toByteArray();
    }

    private static byte[] rawRecoverOperation(byte[] id, long seq, byte[] prev) {
        var p = new DeterministicCborWriter();
        p.writeMapHeader(0);
        var c = new DeterministicCborWriter();
        c.writeMapHeader(6);
        c.writeUnsigned(1);
        c.writeUnsigned(1);
        c.writeUnsigned(2);
        c.writeUnsigned(3);
        c.writeUnsigned(3);
        c.writeByteString(id);
        c.writeUnsigned(4);
        c.writeUnsigned(seq);
        c.writeUnsigned(5);
        c.writeByteString(prev);
        c.writeUnsigned(6);
        c.writeEncoded(p.toByteArray());
        return c.toByteArray();
    }


    @SuppressWarnings("unchecked")
    private static void generateNormativeVectorFile() {
        section("NORMATIVE", "Consolidating OI-002 conformance vectors");
        try {
            Path root = Path.of("..", "..").toAbsolutePath().normalize();
            Path gen = root.resolve("test-vectors").resolve("generated");
            Path tv = root.resolve("test-vectors");
            ObjectMapper mapper = new ObjectMapper();

            List<Map<String, Object>> valid = new java.util.ArrayList<>();
            for (String name : List.of("crypto-v01-java.json", "crypto-v02-java.json", "crypto-v03-java.json", "crypto-v04-java.json")) {
                Map<String, Object> d = mapper.readValue(gen.resolve(name).toFile(), Map.class);
                valid.add((Map<String, Object>) d.get("vector"));
            }
            List<String> validIds = valid.stream().map(v -> (String) v.get("id")).toList();
            if (!validIds.equals(List.of("V01", "V02", "V03", "V04")))
                throw new IllegalStateException("Unexpected valid vector IDs: " + validIds);

            Map<String, Object> idoc = mapper.readValue(gen.resolve("crypto-invalid-java.json").toFile(), Map.class);
            List<Map<String, Object>> invalid = (List<Map<String, Object>>) idoc.get("vectors");
            List<String> expected = java.util.stream.IntStream.rangeClosed(1, 20)
                    .mapToObj(i -> String.format("I%02d", i)).toList();
            List<String> actual = invalid.stream().map(v -> (String) v.get("id")).toList();
            if (!actual.equals(expected)) throw new IllegalStateException("Unexpected invalid vector IDs: " + actual);

            Map<String, Object> ed = new LinkedHashMap<>();
            ed.put("coseKeyType", 1);
            ed.put("coseAlgorithm", -8);
            ed.put("coseCurve", 6);
            ed.put("publicKeyLength", 32);
            ed.put("signatureLength", 64);
            Map<String, Object> ml = new LinkedHashMap<>();
            ml.put("coseKeyType", 7);
            ml.put("coseAlgorithm", -49);
            ml.put("publicKeyLength", 1952);
            ml.put("signatureLength", 3309);
            Map<String, Object> algorithms = new LinkedHashMap<>();
            algorithms.put("Ed25519", ed);
            algorithms.put("ML-DSA-65", ml);

            Map<String, Object> stateHash = new LinkedHashMap<>();
            stateHash.put("multihashAlgorithm", "sha2-256");
            stateHash.put("multihashCode", 18);
            stateHash.put("digestLength", 32);
            stateHash.put("multihashLength", 34);

            Map<String, Object> norm = new LinkedHashMap<>();
            norm.put("specification", "OpenIdentity Cryptographic Agility");
            norm.put("version", "0.1");
            norm.put("wireProtocolVersion", 1);
            norm.put("identityStateVersion", 1);
            norm.put("algorithms", algorithms);
            norm.put("stateHash", stateHash);
            norm.put("valid", valid);
            norm.put("invalid", invalid);

            ObjectMapper output = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
            output.writeValue(tv.resolve("cryptographic-agility-v0.1.json").toFile(), norm);
            success("V01-V04 consolidated");
            success("I01-I20 consolidated");
            success("cryptographic-agility-v0.1.json");
            blankLine();
        } catch (IOException e) {
            throw new IllegalStateException("Unable to generate normative OI-002 vector file", e);
        }
    }

    private static void section(String id, String description) {
        System.out.println("[" + id + "] " + description);
    }

    private static void success(String message) {
        System.out.println("      [OK] " + message);
    }

    private static void blankLine() {
        System.out.println();
    }

    private static Map<String, Object> doc(Map<String, Object> v) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("specification", "OpenIdentity Cryptographic Agility");
        d.put("version", "0.1");
        d.put("vector", v);
        return d;
    }

    private static void put(Map<String, Object> m, String k, byte[] v) {
        m.put(k, Hex.encode(v));
    }

    private static void same(String n, byte[] a, byte[] b) {
        if (!Arrays.equals(a, b)) throw new IllegalStateException(n + " differs from V02");
    }

    private static void writeJson(String filename, Map<String, Object> document) {
        try {
            Path root = Path.of("..", "..").toAbsolutePath().normalize(), dir = root.resolve("test-vectors").resolve("generated");
            Files.createDirectories(dir);
            ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
            Path file = dir.resolve(filename);
            mapper.writeValue(file.toFile(), document);
            System.out.println("Generated JSON:\n" + file + "\n");
        } catch (IOException e) {
            throw new IllegalStateException("Unable to write generated vector JSON", e);
        }
    }
}
