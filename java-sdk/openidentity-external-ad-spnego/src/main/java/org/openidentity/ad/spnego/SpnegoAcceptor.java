package org.openidentity.ad.spnego;
import org.ietf.jgss.*;import javax.security.auth.*;import javax.security.auth.login.*;import javax.security.auth.callback.*;import java.nio.file.*;import java.security.*;import java.util.*;

public final class SpnegoAcceptor {
 public record Result(boolean established,String principal,byte[] responseToken){public Result{responseToken=responseToken==null?new byte[0]:responseToken.clone();}@Override public byte[] responseToken(){return responseToken.clone();}}
 public final class Exchange implements AutoCloseable {
  private GSSContext context;private boolean closed;
  private Exchange(){try{context=Subject.doAs(subject,(PrivilegedExceptionAction<GSSContext>)()->GSSManager.getInstance().createContext((GSSCredential)null));}catch(PrivilegedActionException e){throw new IllegalStateException(e.getException());}}
  public Result accept(byte[] token){if(closed||token==null||token.length==0)throw new IllegalArgumentException("SPNEGO exchange/token");try{return Subject.doAs(subject,(PrivilegedExceptionAction<Result>)()->{byte[] out=context.acceptSecContext(token,0,token.length);if(!context.isEstablished())return new Result(false,null,out);GSSName src=context.getSrcName();if(src==null)throw new GSSException(GSSException.NO_CRED);return new Result(true,src.toString(),out);});}catch(PrivilegedActionException e){close();throw new IllegalArgumentException("SPNEGO verification failed",e.getException());}}
  public void close(){if(closed)return;closed=true;if(context!=null)try{context.dispose();}catch(GSSException ignored){}context=null;}
 }
 private final Subject subject;
 public SpnegoAcceptor(String servicePrincipal,Path keytab){Objects.requireNonNull(servicePrincipal);Objects.requireNonNull(keytab);Configuration cfg=new Configuration(){public AppConfigurationEntry[] getAppConfigurationEntry(String n){Map<String,Object> o=new HashMap<>();o.put("useKeyTab","true");o.put("keyTab",keytab.toAbsolutePath().toString());o.put("principal",servicePrincipal);o.put("storeKey","true");o.put("doNotPrompt","true");o.put("isInitiator","false");o.put("refreshKrb5Config","true");return new AppConfigurationEntry[]{new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,o)};}};try{LoginContext lc=new LoginContext("OpenIdentitySpnego",null,new NoCallbacks(),cfg);lc.login();subject=lc.getSubject();}catch(LoginException e){throw new IllegalStateException("Kerberos acceptor login failed",e);}}
 public Exchange begin(){return new Exchange();}
 private static final class NoCallbacks implements CallbackHandler{public void handle(Callback[] c){if(c.length!=0)throw new UnsupportedOperationException("callbacks not allowed");}}
}