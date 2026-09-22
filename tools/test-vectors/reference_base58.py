"""
Dependency-free reference implementation of Bitcoin Base58 encoding/decoding.

Used only as an independent reference implementation for the
OpenIdentity protocol test vectors.

This file intentionally has ZERO third-party dependencies.
"""

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

ALPHABET_INDEX = {
    character: index
    for index, character in enumerate(ALPHABET)
}


def base58btc_encode(data: bytes) -> str:
    """
    Encode bytes using the Bitcoin Base58 alphabet.

    Leading zero bytes are encoded as the character '1'.

    Args:
        data: Raw bytes to encode.

    Returns:
        Base58btc encoded string WITHOUT the Multibase 'z' prefix.
    """

    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")

    if len(data) == 0:
        return ""

    # Count leading zero bytes.
    zero_count = 0

    for byte in data:
        if byte == 0:
            zero_count += 1
        else:
            break

    # Interpret the bytes as one unsigned big-endian integer.
    number = int.from_bytes(
        data,
        byteorder="big",
        signed=False
    )

    encoded = []

    while number > 0:
        number, remainder = divmod(number, 58)
        encoded.append(ALPHABET[remainder])

    # Digits were generated least-significant first.
    encoded.reverse()

    return ("1" * zero_count) + "".join(encoded)


def base58btc_decode(value: str) -> bytes:
    """
    Decode a Bitcoin Base58 encoded string.

    The input MUST NOT contain the Multibase 'z' prefix.

    Args:
        value: Base58btc encoded string.

    Returns:
        Decoded bytes.

    Raises:
        TypeError:
            If value is not a string.

        ValueError:
            If value contains an invalid Base58btc character.
    """

    if not isinstance(value, str):
        raise TypeError("value must be a string")

    if value == "":
        return b""

    # Count leading '1' characters.
    # Each leading '1' represents one leading zero byte.
    zero_count = 0

    for character in value:
        if character == "1":
            zero_count += 1
        else:
            break

    number = 0

    for character in value:

        if character not in ALPHABET_INDEX:
            raise ValueError(
                f"Invalid base58btc character: {character!r}"
            )

        number = (
                number * 58
                + ALPHABET_INDEX[character]
        )

    if number == 0:
        decoded = b""
    else:
        decoded = number.to_bytes(
            (number.bit_length() + 7) // 8,
            byteorder="big",
            signed=False
        )

    return (b"\x00" * zero_count) + decoded


def multibase_base58btc_encode(data: bytes) -> str:
    """
    Encode bytes using Multibase base58btc.

    Returns:
        'z' + base58btc(data)
    """

    return "z" + base58btc_encode(data)


def multibase_base58btc_decode(value: str) -> bytes:
    """
    Decode a Multibase base58btc value.
    """

    if not isinstance(value, str):
        raise TypeError("value must be a string")

    if not value.startswith("z"):
        raise ValueError(
            "Multibase base58btc value must start with 'z'"
        )

    payload = value[1:]

    if payload == "":
        raise ValueError(
            "Multibase base58btc payload cannot be empty"
        )

    return base58btc_decode(payload)


if __name__ == "__main__":

    vectors = [
        (
            "V01 - 32 zero bytes",
            bytes.fromhex(
                "00" * 32
            )
        ),
        (
            "V02 - Sequential bytes 00 through 1f",
            bytes.fromhex(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
            )
        ),
        (
            "V03 - Maximum 256-bit value",
            bytes.fromhex(
                "ff" * 32
            )
        ),
    ]

    print()
    print("OpenIdentity Base58btc Reference Implementation")
    print("=" * 50)
    print()

    for name, data in vectors:

        encoded = base58btc_encode(data)

        multibase = multibase_base58btc_encode(
            data
        )

        decoded = base58btc_decode(
            encoded
        )

        assert decoded == data

        print(name)
        print("-" * len(name))

        print(
            f"Input Hex:      "
            f"{data.hex()}"
        )

        print(
            f"Base58btc:      "
            f"{encoded}"
        )

        print(
            f"Multibase:      "
            f"{multibase}"
        )

        print(
            f"DID:            "
            f"did:open:{multibase}"
        )

        print(
            f"Decoded Length: "
            f"{len(decoded)}"
        )

        print()