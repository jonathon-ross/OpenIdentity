package org.openidentity.samples;

import com.fasterxml.jackson.databind.*;import org.openidentity.auth.*;import org.openidentity.cbor.StrictCborReader;import org.openidentity.delegation.*;import org.openidentity.oauth.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;import org.springframework.beans.factory.annotation.Value;import org.springframework.context.annotation.*;import java.nio.charset.StandardCharsets;import java.nio.file.*;import java.time.Instant;import java.util.*;

@Configuration
@ConditionalOnProperty(name="openidentity.wallet-dir")
public class WalletBackedExchangeConfiguration {
 static final ObjectMapper J=new ObjectMapper();static final HexFormat H=HexFormat.of();static final byte[] DOMAIN="openidentity:wallet:agent-grants:v1".getBytes(StandardCharsets.UTF_8);
 @Bean @Primary DelegatedAgentExchangeService walletExchange(@Value("${openidentity.wallet-dir}")String d)throws Exception{
  Path dir=Path.of(d);JsonNode wallet=J.readTree(dir.resolve("wallet.json").toFile());byte[] root=H.parseHex(wallet.path("identityHex").asText()),rootHash=H.parseHex(wallet.path("stateHashHex").asText()),state=H.parseHex(wallet.path("stateBytesHex").asText());long dg=generation(state,9);
  Map<String,JsonNode> grants=new HashMap<>();try(var s=Files.list(dir.resolve("grants"))){s.forEach(p->{try{JsonNode g=J.readTree(p.toFile());grants.put(g.path("grantIdHex").asText(),g);}catch(Exception e){throw new RuntimeException(e);}});}
  RegisteredGrantStateResolver records=(domain,id)->{JsonNode g=grants.get(H.formatHex(id));return g==null?null:new RegisteredGrantState(DOMAIN,id,1,RegisteredGrantState.ACTIVE,H.parseHex(g.path("rootStateHashHex").asText()),g.path("delegationGeneration").asLong(),g.path("registeredAt").asLong());};
  RootDelegationStateResolver roots=id->Arrays.equals(id,root)?new RootDelegationState(root,rootHash,true,dg):null;
  CapabilityProfileResolver profiles=ph->{for(JsonNode g:grants.values())if(g.path("profileHashHex").asText().equals(H.formatHex(ph)))return new P(ph,g.path("capability").asText());return null;};
  var oi016=new Oi016DelegatedSubjectVerifier(new Oi016Verifier(new DefaultOi014GrantVerifier(records,roots,profiles),profiles),()->Instant.now().getEpochSecond());
  Map<String,CurrentAuthenticationState> agents=new HashMap<>();try(var s=Files.list(dir.resolve("agents"))){s.forEach(p->{try{JsonNode a=J.readTree(p.toFile());byte[] id=H.parseHex(a.path("identityHex").asText()),pk=H.parseHex(a.path("publicKeyHex").asText()),mid=H.parseHex(a.path("keyReference").asText());agents.put(a.path("identityHex").asText(),new CurrentAuthenticationState(id,rootHash,true,new AuthenticationPolicySnapshot(generation(state,8),1,List.of(new AuthenticationMethod(mid,pk)))));}catch(Exception e){throw new RuntimeException(e);}});}
  AuthenticationStateResolver auth=id->agents.get(H.formatHex(id));var oi015=new Oi015AuthenticationAssertionVerifier(new Oi015Verifier(auth,300));
  CapabilityMapper mapper=(subject,target,scope)->target.equals("https://api.example.test/")&&subject.effectiveCapabilities().stream().anyMatch(x->x instanceof CapabilityRef cr&&scope.equals(new String(cr.capabilityId(),StandardCharsets.UTF_8)));
  Set<String> used=Collections.synchronizedSet(new HashSet<>());return new DelegatedAgentExchangeService(oi016,oi015,x->x,mapper,id->used.add(H.formatHex(id)),300);
 }
 @Bean @Primary org.openidentity.spring.ActorNonceResolver walletNonce(){return request->request.parameter("openidentity_actor_nonce")==null?new byte[32]:Base64.getUrlDecoder().decode(request.parameter("openidentity_actor_nonce"));}
 static long generation(byte[] state,long label){StrictCborReader r=new StrictCborReader(state);long n=r.readMapHeader();for(long i=0;i<n;i++){long k=r.readUnsigned();if(k==label){StrictCborReader a=new StrictCborReader(r.readEncoded());a.readMapHeader();a.readUnsigned();return a.readUnsigned();}r.skipValue();}throw new IllegalArgumentException();}
 record P(byte[] profileHash,String cap)implements CapabilityProfile{public long maximumGrantLifetimeSeconds(){return 86400;}public int maximumDelegationDepth(){return 1;}public boolean permitsChild(List<CapabilityRef>a,List<CapabilityRef>b){return false;}public List<Object> effectiveCapabilities(List<CapabilityRef> c){return new ArrayList<>(c);}}
}