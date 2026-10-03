package org.openidentity.spring.auth;
import org.junit.jupiter.api.Test;import static org.junit.jupiter.api.Assertions.*;
class OpenIdentityAuthenticationTransactionStoreTest {
 private static OpenIdentityAuthenticationTransactionStore.Transaction pending(){
  return new OpenIdentityAuthenticationTransactionStore.Transaction("challenge","/oauth2/authorize?client_id=c","{}",OpenIdentityAuthenticationTransactionStore.Transaction.State.PENDING,null);
 }
 @Test void authenticatedTransitionPreservesVerifierProducedToken(){
  var s=new OpenIdentityAuthenticationTransactionStore();s.put("t",pending());var token=new OpenIdentityNativeAuthenticationToken(new byte[32],new byte[34]);s.authenticated("t",token);
  var t=s.get("t");assertEquals(OpenIdentityAuthenticationTransactionStore.Transaction.State.AUTHENTICATED,t.state());assertSame(token,t.authentication());
 }
 @Test void rejectedIsTerminalForStoredTransaction(){
  var s=new OpenIdentityAuthenticationTransactionStore();s.put("t",pending());s.rejected("t");assertEquals(OpenIdentityAuthenticationTransactionStore.Transaction.State.REJECTED,s.get("t").state());assertNull(s.get("t").authentication());
 }
 @Test void consumeIsSingleUse(){
  var s=new OpenIdentityAuthenticationTransactionStore();s.put("t",pending());assertNotNull(s.consume("t"));assertNull(s.consume("t"));assertNull(s.get("t"));
 }
}