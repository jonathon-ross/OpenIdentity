package org.openidentity.auth;
import java.util.List;
public record AuthenticationPolicySnapshot(long generation,int threshold,List<AuthenticationMethod> methods){
 public AuthenticationPolicySnapshot{methods=List.copyOf(methods);if(threshold<1||threshold>methods.size())throw new IllegalArgumentException("threshold");}
}
