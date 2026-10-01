package org.openidentity.ad.ldap;
import org.openidentity.ad.*;import java.util.*;
public final class MicrosoftAdInteropProbe {
 public static void main(String[] args){
  Map<String,String> a=parse(args);String host=req(a,"host"),base=req(a,"base-dn"),bind=req(a,"bind-dn"),password=req(a,"bind-password"),principal=req(a,"principal"),profile=a.getOrDefault("profile","microsoft-ad-lab"),service=a.getOrDefault("service","openidentity-ad-link-service");int port=Integer.parseInt(a.getOrDefault("port","389"));byte[] directory=HexFormat.of().parseHex(req(a,"directory-id"));if(directory.length!=16)throw new IllegalArgumentException("directory-id must be 16 bytes");
  var resolver=new LdapAdPrincipalResolver(new LdapAdPrincipalResolver.Profile(profile,host,port,base,bind,password,directory,false));
  var p=resolver.resolve(new AdAuthenticationEvidence(profile,principal,service,ExternalAdBindingV1.KERBEROS_SPNEGO,true,Map.of("interopProbe",true)));
  System.out.println("MICROSOFT AD LDAP INTEROP RESOLVED");
  System.out.println("directoryIdHex="+HexFormat.of().formatHex(p.directoryId()));
  System.out.println("objectGuidLdapOctetsHex="+HexFormat.of().formatHex(p.objectGuid()));
  System.out.println("accountUsable="+p.accountUsable());
 }
 private static Map<String,String> parse(String[] args){Map<String,String> m=new HashMap<>();for(int i=0;i<args.length;i+=2){if(i+1>=args.length||!args[i].startsWith("--"))throw new IllegalArgumentException("expected --key value");if(m.put(args[i].substring(2),args[i+1])!=null)throw new IllegalArgumentException("duplicate "+args[i]);}return m;}
 private static String req(Map<String,String> m,String k){String v=m.get(k);if(v==null||v.isBlank())throw new IllegalArgumentException("missing --"+k);return v;}
}