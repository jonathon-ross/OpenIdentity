package org.openidentity.delegation;
import org.openidentity.oauth.*;
import java.util.Objects;
public final class Oi016DelegatedSubjectVerifier implements DelegatedSubjectVerifier {
 private final Oi016Verifier verifier;private final java.util.function.LongSupplier clock;
 public Oi016DelegatedSubjectVerifier(Oi016Verifier verifier,java.util.function.LongSupplier clock){this.verifier=Objects.requireNonNull(verifier);this.clock=Objects.requireNonNull(clock);}
 @Override public VerifiedDelegatedSubject verify(byte[] exactOi016Bytes){return verifier.verify(exactOi016Bytes,clock.getAsLong());}
}
