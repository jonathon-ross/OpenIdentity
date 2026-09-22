package org.openidentity.vectors;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.util.Arrays;

public final class Ed25519Support {

    private final Ed25519PrivateKeyParameters privateKey;
    private final Ed25519PublicKeyParameters publicKey;

    public Ed25519Support(byte[] seed) {
        if (seed == null) {
            throw new IllegalArgumentException(
                    "Ed25519 seed cannot be null"
            );
        }

        if (seed.length != 32) {
            throw new IllegalArgumentException(
                    "Ed25519 seed must be exactly 32 bytes"
            );
        }

        /*
         * Defensive copy so external mutation of the supplied
         * test seed cannot alter this object's key material.
         */
        byte[] seedCopy =
                Arrays.copyOf(
                        seed,
                        seed.length
                );

        this.privateKey =
                new Ed25519PrivateKeyParameters(
                        seedCopy
                );

        this.publicKey =
                privateKey.generatePublicKey();
    }

    public byte[] publicKey() {
        return publicKey.getEncoded();
    }

    public byte[] sign(byte[] message) {
        if (message == null) {
            throw new IllegalArgumentException(
                    "Message cannot be null"
            );
        }

        Ed25519Signer signer =
                new Ed25519Signer();

        signer.init(
                true,
                privateKey
        );

        signer.update(
                message,
                0,
                message.length
        );

        byte[] signature =
                signer.generateSignature();

        if (signature.length != 64) {
            throw new IllegalStateException(
                    "Unexpected Ed25519 signature length: "
                            + signature.length
            );
        }

        return signature;
    }

    public boolean verify(
            byte[] message,
            byte[] signature
    ) {
        if (message == null) {
            throw new IllegalArgumentException(
                    "Message cannot be null"
            );
        }

        if (signature == null) {
            throw new IllegalArgumentException(
                    "Signature cannot be null"
            );
        }

        if (signature.length != 64) {
            return false;
        }

        Ed25519Signer verifier =
                new Ed25519Signer();

        verifier.init(
                false,
                publicKey
        );

        verifier.update(
                message,
                0,
                message.length
        );

        return verifier.verifySignature(
                signature
        );
    }
}