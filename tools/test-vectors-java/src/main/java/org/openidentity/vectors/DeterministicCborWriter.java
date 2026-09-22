package org.openidentity.vectors;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

public final class DeterministicCborWriter {

    private final ByteArrayOutputStream out =
            new ByteArrayOutputStream();

    public byte[] toByteArray() {
        return out.toByteArray();
    }

    public void writeUnsigned(long value) {
        if (value < 0) {
            throw new IllegalArgumentException(
                    "Unsigned integer cannot be negative"
            );
        }

        writeMajorTypeAndValue(0, value);
    }

    public void writeSigned(long value) {
        if (value >= 0) {
            writeUnsigned(value);
            return;
        }

        /*
         * CBOR negative integer n is encoded as:
         *
         * -1 - n
         *
         * Examples:
         *
         * -1 -> 0
         * -8 -> 7
         */
        long encoded = -1L - value;

        writeMajorTypeAndValue(
                1,
                encoded
        );
    }

    public void writeByteString(byte[] value) {
        if (value == null) {
            throw new IllegalArgumentException(
                    "Byte string cannot be null"
            );
        }

        writeMajorTypeAndValue(
                2,
                value.length
        );

        out.writeBytes(value);
    }

    public void writeTextString(String value) {
        if (value == null) {
            throw new IllegalArgumentException(
                    "Text string cannot be null"
            );
        }

        byte[] bytes =
                value.getBytes(StandardCharsets.UTF_8);

        writeMajorTypeAndValue(
                3,
                bytes.length
        );

        out.writeBytes(bytes);
    }

    public void writeArrayHeader(int size) {
        if (size < 0) {
            throw new IllegalArgumentException(
                    "Array size cannot be negative"
            );
        }

        writeMajorTypeAndValue(
                4,
                size
        );
    }

    public void writeMapHeader(int size) {
        if (size < 0) {
            throw new IllegalArgumentException(
                    "Map size cannot be negative"
            );
        }

        writeMajorTypeAndValue(
                5,
                size
        );
    }

    public void writeNull() {
        out.write(0xf6);
    }

    /**
     * Append an already deterministically encoded CBOR object.
     *
     * The caller is responsible for ensuring the supplied bytes
     * represent valid canonical OpenIdentity CBOR.
     *
     * This is intentionally different from writeByteString().
     */
    public void writeEncoded(byte[] encodedCbor) {
        if (encodedCbor == null) {
            throw new IllegalArgumentException(
                    "Encoded CBOR cannot be null"
            );
        }

        out.writeBytes(encodedCbor);
    }

    private void writeMajorTypeAndValue(
            int majorType,
            long value
    ) {
        if (majorType < 0 || majorType > 7) {
            throw new IllegalArgumentException(
                    "Invalid CBOR major type: " + majorType
            );
        }

        if (value < 0) {
            throw new IllegalArgumentException(
                    "CBOR value cannot be negative here"
            );
        }

        int prefix = majorType << 5;

        if (value <= 23) {

            out.write(
                    prefix | (int) value
            );

        } else if (value <= 0xffL) {

            out.write(
                    prefix | 24
            );

            out.write(
                    (int) value
            );

        } else if (value <= 0xffffL) {

            out.write(
                    prefix | 25
            );

            writeBigEndian(
                    value,
                    2
            );

        } else if (value <= 0xffffffffL) {

            out.write(
                    prefix | 26
            );

            writeBigEndian(
                    value,
                    4
            );

        } else {

            out.write(
                    prefix | 27
            );

            writeBigEndian(
                    value,
                    8
            );
        }
    }

    private void writeBigEndian(
            long value,
            int byteCount
    ) {
        for (
                int i = byteCount - 1;
                i >= 0;
                i--
        ) {
            out.write(
                    (int) (
                            value >>> (i * 8)
                    ) & 0xff
            );
        }
    }
}