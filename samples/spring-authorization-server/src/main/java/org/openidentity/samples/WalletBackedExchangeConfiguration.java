package org.openidentity.samples;

import org.openidentity.auth.*;import org.openidentity.cbor.StrictCborReader;import org.openidentity.delegation.*;import org.openidentity.oauth.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;import org.springframework.beans.factory.annotation.Value;import org.springframework.context.annotation.*;import java.nio.charset.StandardCharsets;import java.nio.file.*;import java.time.Instant;import java.util.*;

@Configuration
@ConditionalOnProperty(name="openidentity.oauth-resolver-bundle")
public class WalletBackedExchangeConfiguration {
 static final HexFormat H=HexFormat.of();static final byte[] DOMAIN="openidentity:wallet:agent-grants:v1".getBytes(StandardCharsets.UTF_8);
 @Bean @Primary DelegatedAgentExchangeService walletExchange(@Value("${openidentity.oauth-resolver-bundle}")String file)throws Exception{
  Properties p=new Properties();try(var r=Files.newBufferedReader(Path.of(file))){p.load(r);}
  byte[] root=H.parseHex(p.getProperty("root.identity")),rootHash=H.parseHex(p.getProperty("root.stateHash")),state=H.parseHex(p.getProperty("root.stateBytes")),gid=H.parseHex(p.getProperty("grant.id")),ph=H.parseHex(p.getProperty("grant.profileHash")),agent=H.parseHex(p.getProperty("agent.identity")),pk=H.parseHex(p.getProperty("agent.publicKey")),mid=H.parseHex(p.getProperty("agent.authenticationMethodId"));
  long dg=generation(state,9),ag=generation(state,8),bound=Long.parseLong(p.getProperty("grant.delegationGeneration")),registered=Long.parseLong(p.getProperty("grant.registeredAt"));
  RegisteredGrantStateResolver records=(d,id)->Arrays.equals(id,gid)?new RegisteredGrantState(DOMAIN,gid,1,RegisteredGrantState.ACTIVE,H.parseHex(p.getProperty("grant.rootStateHash")),bound,registered):null;
  RootDelegationStateResolver roots=id->Arrays.equals(id,root)?new RootDelegationState(root,rootHash,true,dg):null;
  CapabilityProfileResolver profiles=x->Arrays.equals(x,ph)?new P(ph,p.getProperty("grant.capability")):null;
  var oi016=new Oi016DelegatedSubjectVerifier(new Oi016Verifier(new DefaultOi014GrantVerifier(records,roots,profiles),profiles),()->Instant.now().getEpochSecond());
  AuthenticationStateResolver auth=id->Arrays.equals(id,agent)?new CurrentAuthenticationState(agent,rootHash,true,new AuthenticationPolicySnapshot(ag,1,List.of(new AuthenticationMethod(mid,pk)))):null;
  var oi015=new Oi015AuthenticationAssertionVerifier(new Oi015Verifier(auth,300));
  CapabilityMapper mapper=(subject,target,scope)->target.equals("https://api.example.test/")&&subject.effectiveCapabilities().stream().anyMatch(x->x instanceof CapabilityRef cr&&scope.equals(new String(cr.capabilityId(),StandardCharsets.UTF_8)));
  Set<String> used=Collections.synchronizedSet(new HashSet<>());return new DelegatedAgentExchangeService(oi016,oi015,x->x,mapper,id->used.add(H.formatHex(id)),300);
 }
 @Bean @Primary org.openidentity.spring.ActorNonceResolver walletNonce(){return request->request.getParameter("openidentity_actor_nonce")==null?new byte[32]:Base64.getUrlDecoder().decode(request.getParameter("openidentity_actor_nonce"));}
 static long generation(byte[] state,long label){StrictCborReader r=new StrictCborReader(state);long n=r.readMapHeader();for(long i=0;i<n;i++){long k=r.readUnsigned();if(k==label){StrictCborReader a=new StrictCborReader(r.readEncoded());a.readMapHeader();a.readUnsigned();return a.readUnsigned();}r.skipValue();}throw new IllegalArgumentException();}
 record P(byte[] profileHash,String cap)implements CapabilityProfile{public long maximumGrantLifetimeSeconds(){return 86400;}public int maximumDelegationDepth(){return 1;}public boolean permitsChild(List<CapabilityRef>a,List<CapabilityRef>b){return false;}public List<Object> effectiveCapabilities(List<CapabilityRef> c){return new ArrayList<>(c);}}
}