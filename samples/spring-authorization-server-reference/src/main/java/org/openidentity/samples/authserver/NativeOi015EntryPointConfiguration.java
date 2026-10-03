package org.openidentity.samples.authserver;
import jakarta.servlet.http.*;import org.springframework.context.annotation.*;import org.springframework.security.web.AuthenticationEntryPoint;import java.net.URLEncoder;import java.nio.charset.StandardCharsets;
@Configuration @Profile("native-oi015")
public class NativeOi015EntryPointConfiguration {
 @Bean AuthenticationEntryPoint nativeOi015EntryPoint(){return (req,res,ex)->{
  String target=req.getRequestURI()+(req.getQueryString()==null?"":"?"+req.getQueryString());
  if(!target.startsWith("/oauth2/authorize?")){res.sendError(401);return;}
  res.sendRedirect("/openidentity/auth/login?continue="+URLEncoder.encode(target,StandardCharsets.UTF_8));
 };}
}