package org.openidentity.spring.auth;
import java.util.concurrent.*;
public final class InMemoryOpenIdentityAuthenticationContinuationStore implements OpenIdentityAuthenticationContinuationStore {
 private final ConcurrentMap<String,String> targets=new ConcurrentHashMap<>();
 @Override public void put(String id,String target){if(id==null||target==null)throw new IllegalArgumentException();targets.put(id,target);}
 @Override public String consume(String id){return id==null?null:targets.remove(id);}
}