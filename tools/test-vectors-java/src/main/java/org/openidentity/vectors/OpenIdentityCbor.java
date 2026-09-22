package org.openidentity.vectors;

import java.util.*;

public final class OpenIdentityCbor {
    private static final int PROTOCOL_VERSION = 1;
    private static final int CREATE_OPERATION = 1;
    private static final int ROTATE_CONTROLLER_OPERATION = 2;
    private static final int SINGLE_POLICY = 1;
    private static final int THRESHOLD_POLICY = 2;
    private static final int SIGNING_STRUCTURE_VERSION = 1;
    private static final int IDENTITY_STATE_VERSION = 1;
    private static final int IDENTITY_STATUS_ACTIVE = 1;

    private static final String OPERATION_CONTEXT = "OpenIdentity Operation";
    private static final String CONTROLLER_PROOF_CONTEXT =
            "OpenIdentity Controller Proof";

    private OpenIdentityCbor() {}

    public record EncodedVerificationMethod(byte[] id, byte[] encoded) {
        public EncodedVerificationMethod {
            if (id == null || id.length != 16) {
                throw new IllegalArgumentException(
                        "Verification Method ID must be exactly 16 bytes");
            }
            if (encoded == null) {
                throw new IllegalArgumentException(
                        "Encoded VerificationMethod cannot be null");
            }
            id = Arrays.copyOf(id, id.length);
            encoded = Arrays.copyOf(encoded, encoded.length);
        }

        @Override public byte[] id() {
            return Arrays.copyOf(id, id.length);
        }

        @Override public byte[] encoded() {
            return Arrays.copyOf(encoded, encoded.length);
        }
    }

    public record EncodedProof(byte[] verificationMethodId, byte[] encoded) {
        public EncodedProof {
            if (verificationMethodId == null
                    || verificationMethodId.length != 16) {
                throw new IllegalArgumentException(
                        "Verification Method ID must be exactly 16 bytes");
            }
            if (encoded == null) {
                throw new IllegalArgumentException(
                        "Encoded proof cannot be null");
            }
            verificationMethodId = Arrays.copyOf(
                    verificationMethodId,
                    verificationMethodId.length);
            encoded = Arrays.copyOf(encoded, encoded.length);
        }

        @Override public byte[] verificationMethodId() {
            return Arrays.copyOf(
                    verificationMethodId,
                    verificationMethodId.length);
        }

        @Override public byte[] encoded() {
            return Arrays.copyOf(encoded, encoded.length);
        }
    }

    private static final Comparator<byte[]> UNSIGNED_BYTES = (a, b) -> {
        int length = Math.min(a.length, b.length);
        for (int i = 0; i < length; i++) {
            int x = Byte.toUnsignedInt(a[i]);
            int y = Byte.toUnsignedInt(b[i]);
            if (x != y) return Integer.compare(x, y);
        }
        return Integer.compare(a.length, b.length);
    };

    public static byte[] ed25519CoseKey(byte[] publicKey) {
        if (publicKey == null || publicKey.length != 32) {
            throw new IllegalArgumentException(
                    "Ed25519 public key must be exactly 32 bytes");
        }
        var c = new DeterministicCborWriter();
        c.writeMapHeader(4);
        c.writeUnsigned(1); c.writeUnsigned(1);
        c.writeUnsigned(3); c.writeSigned(-8);
        c.writeSigned(-1); c.writeUnsigned(6);
        c.writeSigned(-2); c.writeByteString(publicKey);
        return c.toByteArray();
    }

    public static byte[] mlDsa65CoseKey(byte[] publicKey) {
        if (publicKey == null || publicKey.length != 1952) {
            throw new IllegalArgumentException(
                    "ML-DSA-65 public key must be exactly 1952 bytes");
        }
        var c = new DeterministicCborWriter();
        c.writeMapHeader(3);
        c.writeUnsigned(1); c.writeUnsigned(7);
        c.writeUnsigned(3); c.writeSigned(-49);
        c.writeSigned(-1); c.writeByteString(publicKey);
        return c.toByteArray();
    }

    public static EncodedVerificationMethod verificationMethod(
            byte[] methodId,
            byte[] coseKey) {
        validateMethodId(methodId);
        if (coseKey == null) {
            throw new IllegalArgumentException("COSE_Key cannot be null");
        }
        var c = new DeterministicCborWriter();
        c.writeMapHeader(2);
        c.writeUnsigned(1); c.writeByteString(methodId);
        c.writeUnsigned(2); c.writeEncoded(coseKey);
        return new EncodedVerificationMethod(methodId, c.toByteArray());
    }

    public static byte[] singlePolicy(EncodedVerificationMethod method) {
        if (method == null) {
            throw new IllegalArgumentException(
                    "VerificationMethod cannot be null");
        }
        var c = new DeterministicCborWriter();
        c.writeMapHeader(2);
        c.writeUnsigned(1); c.writeUnsigned(SINGLE_POLICY);
        c.writeUnsigned(2); c.writeArrayHeader(1);
        c.writeEncoded(method.encoded());
        return c.toByteArray();
    }

    public static byte[] thresholdPolicy(
            int threshold,
            List<EncodedVerificationMethod> methods) {
        if (methods == null || methods.isEmpty()
                || threshold < 1 || threshold > methods.size()) {
            throw new IllegalArgumentException("Invalid threshold policy");
        }

        var sorted = new ArrayList<>(methods);
        sorted.sort((a, b) -> UNSIGNED_BYTES.compare(a.id(), b.id()));
        rejectDuplicateMethodIds(sorted);

        var c = new DeterministicCborWriter();
        c.writeMapHeader(3);
        c.writeUnsigned(1); c.writeUnsigned(THRESHOLD_POLICY);
        c.writeUnsigned(2); c.writeUnsigned(threshold);
        c.writeUnsigned(3); c.writeArrayHeader(sorted.size());
        for (var method : sorted) {
            c.writeEncoded(method.encoded());
        }
        return c.toByteArray();
    }

    public static byte[] createOperation(
            byte[] identity,
            byte[] controllerPolicy) {
        validateIdentity(identity);
        if (controllerPolicy == null) {
            throw new IllegalArgumentException(
                    "Controller policy cannot be null");
        }

        var payload = new DeterministicCborWriter();
        payload.writeMapHeader(1);
        payload.writeUnsigned(1);
        payload.writeEncoded(controllerPolicy);

        var c = new DeterministicCborWriter();
        c.writeMapHeader(6);
        c.writeUnsigned(1); c.writeUnsigned(PROTOCOL_VERSION);
        c.writeUnsigned(2); c.writeUnsigned(CREATE_OPERATION);
        c.writeUnsigned(3); c.writeByteString(identity);
        c.writeUnsigned(4); c.writeUnsigned(1);
        c.writeUnsigned(5); c.writeNull();
        c.writeUnsigned(6); c.writeEncoded(payload.toByteArray());
        return c.toByteArray();
    }

    /**
     * ROTATE payload contains ONLY the proposed controller policy.
     * Proof-of-possession is carried outside OperationBytes in field 3
     * of SignedOperation.
     */
    public static byte[] rotateControllerPayload(
            byte[] newControllerPolicy) {
        if (newControllerPolicy == null) {
            throw new IllegalArgumentException(
                    "New controller policy cannot be null");
        }

        var c = new DeterministicCborWriter();
        c.writeMapHeader(1);
        c.writeUnsigned(1);
        c.writeEncoded(newControllerPolicy);
        return c.toByteArray();
    }

    public static byte[] rotateControllerOperation(
            byte[] identity,
            long sequence,
            byte[] previousStateHash,
            byte[] newControllerPolicy) {
        validateIdentity(identity);

        if (sequence < 2) {
            throw new IllegalArgumentException(
                    "ROTATE_CONTROLLER sequence must be >= 2");
        }

        if (previousStateHash == null
                || previousStateHash.length < 1
                || previousStateHash.length > 128) {
            throw new IllegalArgumentException(
                    "Previous state hash must contain 1..128 bytes");
        }

        byte[] payload = rotateControllerPayload(newControllerPolicy);

        var c = new DeterministicCborWriter();
        c.writeMapHeader(6);
        c.writeUnsigned(1); c.writeUnsigned(PROTOCOL_VERSION);
        c.writeUnsigned(2); c.writeUnsigned(ROTATE_CONTROLLER_OPERATION);
        c.writeUnsigned(3); c.writeByteString(identity);
        c.writeUnsigned(4); c.writeUnsigned(sequence);
        c.writeUnsigned(5); c.writeByteString(previousStateHash);
        c.writeUnsigned(6); c.writeEncoded(payload);
        return c.toByteArray();
    }

    public static byte[] operationSigningInput(byte[] operationBytes) {
        if (operationBytes == null) {
            throw new IllegalArgumentException(
                    "Operation bytes cannot be null");
        }
        var c = new DeterministicCborWriter();
        c.writeArrayHeader(3);
        c.writeTextString(OPERATION_CONTEXT);
        c.writeUnsigned(SIGNING_STRUCTURE_VERSION);
        c.writeByteString(operationBytes);
        return c.toByteArray();
    }

    public static byte[] controllerProofSigningInput(
            byte[] operationBytes,
            byte[] methodId) {
        if (operationBytes == null) {
            throw new IllegalArgumentException(
                    "Operation bytes cannot be null");
        }
        validateMethodId(methodId);

        var c = new DeterministicCborWriter();
        c.writeArrayHeader(4);
        c.writeTextString(CONTROLLER_PROOF_CONTEXT);
        c.writeUnsigned(SIGNING_STRUCTURE_VERSION);
        c.writeByteString(operationBytes);
        c.writeByteString(methodId);
        return c.toByteArray();
    }

    public static EncodedProof authorizationProof(
            byte[] methodId,
            byte[] signature) {
        return proof(methodId, signature);
    }

    public static EncodedProof controllerProof(
            byte[] methodId,
            byte[] signature) {
        return proof(methodId, signature);
    }

    private static EncodedProof proof(
            byte[] methodId,
            byte[] signature) {
        validateMethodId(methodId);
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException(
                    "Signature cannot be null or empty");
        }

        var c = new DeterministicCborWriter();
        c.writeMapHeader(2);
        c.writeUnsigned(1); c.writeByteString(methodId);
        c.writeUnsigned(2); c.writeByteString(signature);
        return new EncodedProof(methodId, c.toByteArray());
    }

    /**
     * CREATE and other operations without controller PoP.
     */
    public static byte[] signedOperation(
            byte[] operation,
            List<EncodedProof> authorizationProofs) {
        return signedOperation(
                operation,
                authorizationProofs,
                List.of());
    }

    /**
     * Full envelope:
     *
     * {
     *   1: operation,
     *   2: authorizationProofs,
     *   3: controllerProofs     // omitted when empty
     * }
     *
     * Controller proofs are deliberately outside OperationBytes.
     */
    public static byte[] signedOperation(
            byte[] operation,
            List<EncodedProof> authorizationProofs,
            List<EncodedProof> controllerProofs) {

        if (operation == null) {
            throw new IllegalArgumentException(
                    "Operation cannot be null");
        }

        List<EncodedProof> auth = canonicalProofs(
                authorizationProofs,
                "authorization proof");

        List<EncodedProof> pop =
                controllerProofs == null || controllerProofs.isEmpty()
                        ? List.of()
                        : canonicalProofs(
                        controllerProofs,
                        "controller proof");

        var c = new DeterministicCborWriter();
        c.writeMapHeader(pop.isEmpty() ? 2 : 3);

        c.writeUnsigned(1);
        c.writeEncoded(operation);

        c.writeUnsigned(2);
        c.writeArrayHeader(auth.size());
        for (var proof : auth) {
            c.writeEncoded(proof.encoded());
        }

        if (!pop.isEmpty()) {
            c.writeUnsigned(3);
            c.writeArrayHeader(pop.size());
            for (var proof : pop) {
                c.writeEncoded(proof.encoded());
            }
        }

        return c.toByteArray();
    }

    public static byte[] activeIdentityState(
            byte[] identity,
            long sequence,
            byte[] controllerPolicy) {
        validateIdentity(identity);
        if (sequence < 1) {
            throw new IllegalArgumentException(
                    "State sequence must be >= 1");
        }
        if (controllerPolicy == null) {
            throw new IllegalArgumentException(
                    "Controller policy cannot be null");
        }

        var c = new DeterministicCborWriter();
        c.writeMapHeader(5);
        c.writeUnsigned(1); c.writeUnsigned(IDENTITY_STATE_VERSION);
        c.writeUnsigned(2); c.writeByteString(identity);
        c.writeUnsigned(3); c.writeUnsigned(sequence);
        c.writeUnsigned(4); c.writeUnsigned(IDENTITY_STATUS_ACTIVE);
        c.writeUnsigned(5); c.writeEncoded(controllerPolicy);
        return c.toByteArray();
    }

    private static List<EncodedProof> canonicalProofs(
            List<EncodedProof> proofs,
            String kind) {
        if (proofs == null || proofs.isEmpty()) {
            throw new IllegalArgumentException(
                    "At least one " + kind + " is required");
        }

        var sorted = new ArrayList<>(proofs);
        sorted.sort((a, b) -> UNSIGNED_BYTES.compare(
                a.verificationMethodId(),
                b.verificationMethodId()));

        for (int i = 1; i < sorted.size(); i++) {
            if (Arrays.equals(
                    sorted.get(i - 1).verificationMethodId(),
                    sorted.get(i).verificationMethodId())) {
                throw new IllegalArgumentException(
                        "Duplicate " + kind);
            }
        }
        return sorted;
    }

    private static void rejectDuplicateMethodIds(
            List<EncodedVerificationMethod> methods) {
        for (int i = 1; i < methods.size(); i++) {
            if (Arrays.equals(
                    methods.get(i - 1).id(),
                    methods.get(i).id())) {
                throw new IllegalArgumentException(
                        "Duplicate Verification Method ID");
            }
        }
    }

    private static void validateIdentity(byte[] identity) {
        if (identity == null || identity.length != 32) {
            throw new IllegalArgumentException(
                    "Identity must be exactly 32 bytes");
        }
    }

    private static void validateMethodId(byte[] methodId) {
        if (methodId == null || methodId.length != 16) {
            throw new IllegalArgumentException(
                    "Verification Method ID must be exactly 16 bytes");
        }
    }
}
