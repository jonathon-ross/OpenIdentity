package org.openidentity.auth;
import org.openidentity.oauth.*;
import java.util.Objects;
public final class Oi015AuthenticationAssertionVerifier implements AuthenticationAssertionVerifier {
 private final Oi015Verifier verifier;
 public Oi015AuthenticationAssertionVerifier(Oi015Verifier verifier){this.verifier=Objects.requireNonNull(verifier);}
 @Override public VerifiedAuthenticationAssertion verify(AuthenticationVerificationRequest r){
  SecuredAuthenticationAssertion s;try{s=Oi015Codec.decode(r.securedAssertionBytes());}catch(IllegalArgumentException e){throw new ProfileException(ProfileError.INVALID_REQUEST,e);}
  return verifier.verify(s,r.expectedAudience(),r.expectedPurpose(),r.expectedNonce(),r.expectedContextHash(),r.verificationTime());
 }
}
