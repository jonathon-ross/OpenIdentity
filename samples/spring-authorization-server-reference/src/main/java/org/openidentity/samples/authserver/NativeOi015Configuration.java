package org.openidentity.samples.authserver;
import org.openidentity.auth.*;import org.openidentity.core.*;import org.openidentity.spring.auth.*;import org.springframework.beans.factory.annotation.Value;import org.springframework.context.annotation.*;import java.nio.charset.StandardCharsets;import java.nio.file.Path;import java.security.SecureRandom;import java.time.Clock;
@Configuration @Profile("native-oi015")
public class NativeOi015Configuration {
 @Bean FileCanonicalIdentityStateRepository nativeStateRepository(@Value("${OPENIDENTITY_STATE_DIR}") String dir){return new FileCanonicalIdentityStateRepository(Path.of(dir));}
 @Bean Oi015Verifier nativeOi015Verifier(FileCanonicalIdentityStateRepository repo){return new Oi015Verifier(new CanonicalAuthenticationStateResolver(repo),300);}
 @Bean OpenIdentityAuthenticationChallengeStore nativeChallengeStore(){return new InMemoryOpenIdentityAuthenticationChallengeStore();}
 @Bean OpenIdentityAuthenticationService nativeAuthenticationService(Oi015Verifier verifier,OpenIdentityAuthenticationChallengeStore store,@Value("${openidentity.authorization-server.issuer:http://127.0.0.1:9000}") String issuer){return new OpenIdentityAuthenticationService(verifier,store,issuer.getBytes(StandardCharsets.UTF_8),Clock.systemUTC(),new SecureRandom(),120);}
 @Bean OpenIdentityAuthenticationHttpController nativeAuthenticationController(OpenIdentityAuthenticationService service){return new OpenIdentityAuthenticationHttpController(service);}
 @Bean OpenIdentityAuthenticationContinuationStore nativeContinuationStore(){return new InMemoryOpenIdentityAuthenticationContinuationStore();}
 @Bean OpenIdentityOAuthContinuationController nativeOAuthContinuationController(OpenIdentityAuthenticationService service,OpenIdentityAuthenticationContinuationStore store){return new OpenIdentityOAuthContinuationController(service,store);}
 @Bean OpenIdentityNativeLoginPageController nativeLoginPageController(){return new OpenIdentityNativeLoginPageController();}
}