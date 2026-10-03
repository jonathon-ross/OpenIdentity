package org.openidentity.spring.auth;
import java.security.SecureRandom;import java.util.*;import java.util.concurrent.*;
public final class InMemoryOpenIdentityAuthenticationChallengeStore implements OpenIdentityAuthenticationChallengeStore {
 private final Map<String,OpenIdentityAuthenticationChallenge> challenges=new ConcurrentHashMap<>();private final SecureRandom random=new SecureRandom();
 @Override public String create(OpenIdentityAuthenticationChallenge c){byte[] id=new byte[32];random.nextBytes(id);String key=HexFormat.of().formatHex(id);challenges.put(key,c);return key;}
 @Override public OpenIdentityAuthenticationChallenge consume(String id){return id==null?null:challenges.remove(id);}
}