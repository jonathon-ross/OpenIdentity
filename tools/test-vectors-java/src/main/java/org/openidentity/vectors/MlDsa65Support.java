package org.openidentity.vectors;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;

public final class MlDsa65Support {

    private static final String PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "MLDSA";
    private static final String SIGNATURE_ALGORITHM = "MLDSA";

    private static final int SEED_LENGTH = 32;
    private static final int PUBLIC_KEY_LENGTH = 1952;
    private static final int SIGNATURE_LENGTH = 3309;

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    static {
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(
                    new BouncyCastleProvider()
            );
        }
    }

    public MlDsa65Support(byte[] seed) {

        if (seed == null) {
            throw new IllegalArgumentException(
                    "ML-DSA-65 seed cannot be null"
            );
        }

        if (seed.length != SEED_LENGTH) {
            throw new IllegalArgumentException(
                    "ML-DSA-65 test seed must be exactly "
                            + SEED_LENGTH
                            + " bytes"
            );
        }

        try {

            /*
             * IMPORTANT:
             *
             * This SecureRandom exists ONLY so that the test-vector
             * key pair is reproducible.
             *
             * It MUST NOT be copied into production OpenIdentity
             * key generation.
             */
            SecureRandom deterministicRandom =
                    new FixedSecureRandom(seed);

            KeyPairGenerator generator =
                    KeyPairGenerator.getInstance(
                            KEY_ALGORITHM,
                            PROVIDER
                    );

            generator.initialize(
                    MLDSAParameterSpec.ml_dsa_65,
                    deterministicRandom
            );

            KeyPair keyPair =
                    generator.generateKeyPair();

            this.privateKey =
                    keyPair.getPrivate();

            this.publicKey =
                    keyPair.getPublic();

        } catch (Exception e) {

            throw new IllegalStateException(
                    "Unable to generate deterministic "
                            + "ML-DSA-65 test key pair",
                    e
            );
        }
    }

    /**
     * Return the raw ML-DSA-65 public key required by the
     * OpenIdentity COSE AKP representation.
     *
     * Do NOT use PublicKey.getEncoded() here because that returns
     * an X.509 SubjectPublicKeyInfo representation rather than the
     * 1952-byte raw ML-DSA public key.
     */
    public byte[] publicKey() {

        try {

            /*
             * Bouncy Castle exposes the encoded Java public key as
             * SubjectPublicKeyInfo. For the OpenIdentity COSE_Key,
             * we need the raw ML-DSA public-key bytes.
             *
             * Use the BC key object's getPublicData() method when
             * available.
             */

            var method =
                    publicKey
                            .getClass()
                            .getMethod(
                                    "getPublicData"
                            );

            byte[] raw =
                    (byte[]) method.invoke(
                            publicKey
                    );

            if (raw.length != PUBLIC_KEY_LENGTH) {
                throw new IllegalStateException(
                        "Unexpected ML-DSA-65 public key length: "
                                + raw.length
                                + "; expected "
                                + PUBLIC_KEY_LENGTH
                );
            }

            return Arrays.copyOf(
                    raw,
                    raw.length
            );

        } catch (ReflectiveOperationException e) {

            throw new IllegalStateException(
                    "Unable to extract raw ML-DSA-65 "
                            + "public key from Bouncy Castle key",
                    e
            );
        }
    }

    /**
     * Produce a deterministic ML-DSA-65 signature.
     *
     * IMPORTANT:
     *
     * initSign(privateKey) is intentionally called WITHOUT a
     * SecureRandom.
     *
     * Bouncy Castle documents this as deterministic ML-DSA signing.
     * This behavior is useful for byte-exact protocol test vectors.
     *
     * Production OpenIdentity signing should use the randomized /
     * hedged signing mode unless the production security profile
     * explicitly says otherwise.
     */
    public byte[] sign(byte[] message) {

        if (message == null) {
            throw new IllegalArgumentException(
                    "Message cannot be null"
            );
        }

        try {

            Signature signer =
                    Signature.getInstance(
                            SIGNATURE_ALGORITHM,
                            PROVIDER
                    );

            /*
             * NO SecureRandom here.
             *
             * This deliberately requests deterministic ML-DSA
             * signing for normative test vectors.
             */
            signer.initSign(
                    privateKey
            );

            signer.update(
                    message
            );

            byte[] signature =
                    signer.sign();

            if (signature.length != SIGNATURE_LENGTH) {
                throw new IllegalStateException(
                        "Unexpected ML-DSA-65 signature length: "
                                + signature.length
                                + "; expected "
                                + SIGNATURE_LENGTH
                );
            }

            return signature;

        } catch (Exception e) {

            throw new IllegalStateException(
                    "Unable to generate ML-DSA-65 signature",
                    e
            );
        }
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

        if (signature.length != SIGNATURE_LENGTH) {
            return false;
        }

        try {

            Signature verifier =
                    Signature.getInstance(
                            SIGNATURE_ALGORITHM,
                            PROVIDER
                    );

            verifier.initVerify(
                    publicKey
            );

            verifier.update(
                    message
            );

            return verifier.verify(
                    signature
            );

        } catch (Exception e) {

            throw new IllegalStateException(
                    "Unable to verify ML-DSA-65 signature",
                    e
            );
        }
    }

    /**
     * Deterministic SecureRandom used ONLY to make test-vector
     * key generation reproducible.
     *
     * This is deliberately unsuitable for production cryptography.
     */
    private static final class FixedSecureRandom
            extends SecureRandom {

        private final byte[] seed;
        private int position;

        private FixedSecureRandom(
                byte[] seed
        ) {

            this.seed =
                    Arrays.copyOf(
                            seed,
                            seed.length
                    );

            this.position = 0;
        }

        @Override
        public void nextBytes(
                byte[] bytes
        ) {

            for (
                    int i = 0;
                    i < bytes.length;
                    i++
            ) {

                bytes[i] =
                        seed[
                                position
                                        % seed.length
                                ];

                position++;
            }
        }
    }
}