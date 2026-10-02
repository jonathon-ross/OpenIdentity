package org.openidentity.spring.ad;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;import org.springframework.security.web.context.SecurityContextHolderFilter;import java.util.*;
public final class OpenIdentityActiveDirectorySecurityConfigurer extends AbstractHttpConfigurer<OpenIdentityActiveDirectorySecurityConfigurer,HttpSecurity>{
 private final OpenIdentitySpnegoAuthenticationFilter filter;
 public OpenIdentityActiveDirectorySecurityConfigurer(OpenIdentitySpnegoAuthenticationFilter filter){this.filter=Objects.requireNonNull(filter);}
 @Override public void configure(HttpSecurity http){http.addFilterAfter(filter,SecurityContextHolderFilter.class);}
}