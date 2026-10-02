package org.openidentity.spring.ad;
import org.openidentity.ad.VerifiedAdPrincipal;import java.util.*;
public record OpenIdentityActiveDirectoryAuthentication(String kerberosPrincipal,VerifiedAdPrincipal verifiedPrincipal,byte[] openIdentityId,BindingStatus bindingStatus){
 public enum BindingStatus{UNBOUND,ACTIVE}
 public OpenIdentityActiveDirectoryAuthentication{Objects.requireNonNull(kerberosPrincipal);Objects.requireNonNull(verifiedPrincipal);Objects.requireNonNull(bindingStatus);openIdentityId=openIdentityId==null?null:openIdentityId.clone();if(bindingStatus==BindingStatus.ACTIVE&&(openIdentityId==null||openIdentityId.length!=32))throw new IllegalArgumentException("active binding identity");}
 @Override public byte[] openIdentityId(){return openIdentityId==null?null:openIdentityId.clone();}
 public boolean bound(){return bindingStatus==BindingStatus.ACTIVE;}
}