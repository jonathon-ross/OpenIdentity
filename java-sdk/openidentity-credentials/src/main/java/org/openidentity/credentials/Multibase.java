package org.openidentity.credentials;

import java.util.Base64;

/** Multibase encoders used by the deterministic W3C credential projection. */
public final class Multibase {
  private static final char[] B58 =
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();

  private Multibase() {}

  /**
   * Encodes bytes as unpadded base64url Multibase using the {@code u} prefix.
   *
   * @param bytes input bytes
   * @return Multibase string
   */
  public static String base64Url(byte[] bytes) {
    return "u" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  /**
   * Encodes bytes as base58btc Multibase using the {@code z} prefix.
   *
   * @param input input bytes
   * @return Multibase string
   */
  public static String base58Btc(byte[] input) {
    return "z" + base58(input);
  }

  private static String base58(byte[] input) {
    if (input.length == 0) return "";
    int zeros = 0;
    while (zeros < input.length && input[zeros] == 0) zeros++;
    byte[] work = input.clone();
    char[] out = new char[input.length * 2];
    int outputStart = out.length;
    int inputStart = zeros;
    while (inputStart < work.length) {
      int remainder = 0;
      for (int i = inputStart; i < work.length; i++) {
        int digit = Byte.toUnsignedInt(work[i]);
        int temp = remainder * 256 + digit;
        work[i] = (byte) (temp / 58);
        remainder = temp % 58;
      }
      out[--outputStart] = B58[remainder];
      while (inputStart < work.length && work[inputStart] == 0) inputStart++;
    }
    while (outputStart < out.length && out[outputStart] == B58[0]) outputStart++;
    while (zeros-- > 0) out[--outputStart] = B58[0];
    return new String(out, outputStart, out.length - outputStart);
  }
}
