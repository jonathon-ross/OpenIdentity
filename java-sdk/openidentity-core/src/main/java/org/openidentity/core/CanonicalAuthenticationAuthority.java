package org.openidentity.core;
import java.util.List;
public record CanonicalAuthenticationAuthority(long generation,int threshold,List<CanonicalAuthenticationMethod> methods){
 public CanonicalAuthenticationAuthority{methods=List.copyOf(methods);if(generation<0||threshold<1||threshold>methods.size())throw new IllegalArgumentException("authentication authority");}
}