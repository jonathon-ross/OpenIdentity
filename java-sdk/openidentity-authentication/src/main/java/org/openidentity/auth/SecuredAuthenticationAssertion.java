package org.openidentity.auth;
import java.util.List;
public record SecuredAuthenticationAssertion(AuthenticationAssertion assertion,List<AuthenticationProof> proofs){
 public SecuredAuthenticationAssertion{proofs=List.copyOf(proofs);}
}
