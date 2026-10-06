package org.openidentity.core;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class SequenceTest {
  @Test
  void supportsFullUint64RangeWithoutWrap() {
    Sequence max = new Sequence(Sequence.MAX);
    assertEquals(new BigInteger("18446744073709551615"), max.value());
    assertThrows(ArithmeticException.class, max::next);
    assertThrows(IllegalArgumentException.class, () -> new Sequence(BigInteger.ZERO));
    assertThrows(
        IllegalArgumentException.class, () -> new Sequence(Sequence.MAX.add(BigInteger.ONE)));
  }
}
