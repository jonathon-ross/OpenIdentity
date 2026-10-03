package org.openidentity.samples.nativeauth;
import com.fasterxml.jackson.databind.ObjectMapper;import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;import org.openidentity.core.*;import org.openidentity.crypto.Sha256Multihash;import java.nio.charset.StandardCharsets;import java.nio.file.*;import java.security.MessageDigest;import java.util.*;
public final class NativeOi015FixtureGenerator {
 static byte[] sha(String s)throws Exception{return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));}
 public static void main(String[] args)throws Exception{
  if(args.length!=1){System.err.println("usage: NativeOi015FixtureGenerator <state-dir>");System.exit(2);}
  byte[] identity=sha("openidentity-native-oi015-reference-identity"),seed=sha("openidentity-native-oi015-reference-private-seed"),method=Arrays.copyOf(sha("openidentity-native-oi015-reference-method"),16),stateHash=Sha256Multihash.digest(sha("openidentity-native-oi015-reference-state"));
  var key=new Ed25519PrivateKeyParameters(seed,0);var authority=new CanonicalAuthenticationAuthority(1,1,List.of(new CanonicalAuthenticationMethod(method,key.generatePublicKey().getEncoded())));var state=new CanonicalIdentityState(identity,stateHash,true,authority);new FileCanonicalIdentityStateRepository(Path.of(args[0])).save(state);
  var j=new ObjectMapper().createObjectNode();var h=HexFormat.of();j.put("identityHex",h.formatHex(identity));j.put("methodIdHex",h.formatHex(method));j.put("privateSeedHex",h.formatHex(seed));j.put("stateDirectory",Path.of(args[0]).toAbsolutePath().normalize().toString());System.out.println(new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(j));
 }
}