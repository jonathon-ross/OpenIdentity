package org.openidentity.vectors;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class StateHash {
    private StateHash() {
    }

    public static byte[] sha256Multihash(byte[] stateBytes) {
        if (stateBytes == null) throw new IllegalArgumentException("State bytes cannot be null");
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(stateBytes);
            byte[] out = new byte[34];
            out[0] = 0x12;
            out[1] = 0x20;
            System.arraycopy(digest, 0, out, 2, 32);
            return out;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
