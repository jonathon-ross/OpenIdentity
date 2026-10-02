package org.openidentity.spring.ad;
import java.nio.file.Path;import java.util.*;
public record OpenIdentityActiveDirectoryProperties(boolean enabled,Kerberos kerberos,Ldap ldap,Bindings bindings){
 public record Kerberos(String servicePrincipal,Path keytab){}
 public record Ldap(String profileId,String host,int port,String baseDn,String bindPrincipal,byte[] directoryId){
  public Ldap{directoryId=directoryId==null?null:directoryId.clone();}@Override public byte[] directoryId(){return directoryId==null?null:directoryId.clone();}
 }
 public record Bindings(Path store){}
}