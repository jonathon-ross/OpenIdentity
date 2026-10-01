package org.openidentity.ad.ldap;
public final class LdapAdResolutionException extends RuntimeException{
 private final int ldapResultCode;
 public LdapAdResolutionException(int ldapResultCode,String diagnostic,Throwable cause){super("LDAP operation failed (resultCode="+ldapResultCode+"): "+(diagnostic==null?"":diagnostic),cause);this.ldapResultCode=ldapResultCode;}
 public int ldapResultCode(){return ldapResultCode;}
}