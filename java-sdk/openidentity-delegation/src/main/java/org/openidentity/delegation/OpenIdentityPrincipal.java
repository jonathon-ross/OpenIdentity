package org.openidentity.delegation;
public record OpenIdentityPrincipal(byte[] identity) implements Principal {
 public OpenIdentityPrincipal{identity=identity.clone();if(identity.length!=32)throw new IllegalArgumentException("identity length");}
 @Override public byte[] identity(){return identity.clone();}
}
