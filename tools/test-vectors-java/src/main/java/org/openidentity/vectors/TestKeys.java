package org.openidentity.vectors;

public final class TestKeys {

    private TestKeys() {
    }

    /*
     * TEST MATERIAL ONLY.
     *
     * These values MUST NEVER be used as production
     * cryptographic keys.
     */

    public static final byte[] IDENTITY =
            Hex.decode(
                    """
                    000102030405060708090a0b0c0d0e0f
                    101112131415161718191a1b1c1d1e1f
                    """
            );

    public static final byte[] ED25519_METHOD_ID =
            Hex.decode(
                    """
                    000102030405060708090a0b0c0d0e0f
                    """
            );

    public static final byte[] ML_DSA_METHOD_ID =
            Hex.decode(
                    """
                    101112131415161718191a1b1c1d1e1f
                    """
            );

    public static final byte[] ED25519_SEED =
            Hex.decode(
                    """
                    000102030405060708090a0b0c0d0e0f
                    101112131415161718191a1b1c1d1e1f
                    """
            );

    public static final byte[] ML_DSA_SEED =
            Hex.decode(
                    """
                    202122232425262728292a2b2c2d2e2f
                    303132333435363738393a3b3c3d3e3f
                    """
            );

    public static final byte[] ED25519_METHOD_ID_B =
            Hex.decode(
                    """
                    202122232425262728292a2b2c2d2e2f
                    """
            );

    public static final byte[] ML_DSA_METHOD_ID_B =
            Hex.decode(
                    """
                    303132333435363738393a3b3c3d3e3f
                    """
            );

    public static final byte[] ED25519_SEED_B =
            Hex.decode(
                    """
                    404142434445464748494a4b4c4d4e4f
                    505152535455565758595a5b5c5d5e5f
                    """
            );

    public static final byte[] ML_DSA_SEED_B =
            Hex.decode(
                    """
                    606162636465666768696a6b6c6d6e6f
                    707172737475767778797a7b7c7d7e7f
                    """
            );
}