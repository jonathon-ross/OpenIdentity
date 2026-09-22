package org.openidentity.vectors;

import java.util.HexFormat;

public final class Hex {

    private static final HexFormat HEX = HexFormat.of();

    private Hex() {
    }

    public static byte[] decode(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Hex value cannot be null");
        }

        return HEX.parseHex(
                value.replaceAll("\\s+", "")
        );
    }

    public static String encode(byte[] value) {
        if (value == null) {
            throw new IllegalArgumentException("Value cannot be null");
        }

        return HEX.formatHex(value);
    }
}