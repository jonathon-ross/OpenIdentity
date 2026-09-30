package org.openidentity.spring;
import org.springframework.security.oauth2.jwt.Jwt;
import java.util.Objects;
public record ValidatedDpopProofResult(String jkt,Jwt proof){
 public ValidatedDpopProofResult{Objects.requireNonNull(jkt);Objects.requireNonNull(proof);}
}
