package org.openidentity.core;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Monotonically increasing OpenIdentity operation sequence number.
 *
 * <p>Protocol sequences are unsigned 64-bit integers in the range {@code 1..2^64-1}. CREATE uses
 * sequence 1; every subsequent state transition must use exactly the predecessor sequence plus one.
 *
 * @param value unsigned protocol sequence value
 */
public record Sequence(BigInteger value) implements Comparable<Sequence> {
  /** Minimum valid sequence value. */
  public static final BigInteger MIN = BigInteger.ONE;

  /** Maximum valid sequence value ({@code 2^64-1}). */
  public static final BigInteger MAX = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);

  /** Validates a sequence value. */
  public Sequence {
    Objects.requireNonNull(value, "value");
    if (value.compareTo(MIN) < 0 || value.compareTo(MAX) > 0) {
      throw new IllegalArgumentException("Sequence must be in uint64 range 1..2^64-1");
    }
  }

  /**
   * Creates a sequence from a positive signed {@code long}.
   *
   * @param value sequence value
   * @return validated sequence
   * @throws IllegalArgumentException if the value is outside the protocol range
   */
  public static Sequence of(long value) {
    return new Sequence(BigInteger.valueOf(value));
  }

  /**
   * Returns the immediately following protocol sequence.
   *
   * @return next sequence
   * @throws ArithmeticException if this sequence is already {@link #MAX}
   */
  public Sequence next() {
    if (value.equals(MAX)) {
      throw new ArithmeticException("OpenIdentity sequence exhausted");
    }
    return new Sequence(value.add(BigInteger.ONE));
  }

  @Override
  public int compareTo(Sequence other) {
    return value.compareTo(other.value);
  }
}
