package org.openidentity.spring.ad;
import org.springframework.boot.context.properties.ConfigurationProperties;import java.nio.file.Path;

@ConfigurationProperties("openidentity.active-directory")
public class OpenIdentityActiveDirectoryProperties {
 private boolean enabled;private final Kerberos kerberos=new Kerberos();private final Ldap ldap=new Ldap();private final Bindings bindings=new Bindings();
 public boolean isEnabled(){return enabled;}public void setEnabled(boolean v){enabled=v;}public Kerberos getKerberos(){return kerberos;}public Ldap getLdap(){return ldap;}public Bindings getBindings(){return bindings;}
 public static final class Kerberos{private String servicePrincipal;private Path keytab;public String getServicePrincipal(){return servicePrincipal;}public void setServicePrincipal(String v){servicePrincipal=v;}public Path getKeytab(){return keytab;}public void setKeytab(Path v){keytab=v;}}
 public static final class Ldap{private String profileId="microsoft-ad",host;private int port=636;private String baseDn,bindPrincipal,directoryIdHex;public String getProfileId(){return profileId;}public void setProfileId(String v){profileId=v;}public String getHost(){return host;}public void setHost(String v){host=v;}public int getPort(){return port;}public void setPort(int v){port=v;}public String getBaseDn(){return baseDn;}public void setBaseDn(String v){baseDn=v;}public String getBindPrincipal(){return bindPrincipal;}public void setBindPrincipal(String v){bindPrincipal=v;}public String getDirectoryIdHex(){return directoryIdHex;}public void setDirectoryIdHex(String v){directoryIdHex=v;}}
 public static final class Bindings{private Path store,stateDirectory;public Path getStore(){return store;}public void setStore(Path v){store=v;}public Path getStateDirectory(){return stateDirectory;}public void setStateDirectory(Path v){stateDirectory=v;}}
}