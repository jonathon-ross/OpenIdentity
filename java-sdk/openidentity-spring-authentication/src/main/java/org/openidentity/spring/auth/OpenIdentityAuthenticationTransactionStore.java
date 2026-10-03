package org.openidentity.spring.auth;
import java.util.concurrent.*;
public final class OpenIdentityAuthenticationTransactionStore {
 public record Transaction(String challengeId,String requestTarget,String challengeJson,State state,OpenIdentityNativeAuthenticationToken authentication){public enum State{PENDING,AUTHENTICATED,REJECTED}}
 private final ConcurrentMap<String,Transaction> transactions=new ConcurrentHashMap<>();
 public void put(String id,Transaction tx){transactions.put(id,tx);}public Transaction get(String id){return transactions.get(id);}
 public void authenticated(String id,OpenIdentityNativeAuthenticationToken authentication){transactions.computeIfPresent(id,(k,v)->new Transaction(v.challengeId(),v.requestTarget(),v.challengeJson(),Transaction.State.AUTHENTICATED,authentication));}
 public void rejected(String id){transactions.computeIfPresent(id,(k,v)->new Transaction(v.challengeId(),v.requestTarget(),v.challengeJson(),Transaction.State.REJECTED,null));}
 public Transaction consume(String id){return transactions.remove(id);}
}