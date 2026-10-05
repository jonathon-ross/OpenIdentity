package org.openidentity.samples;

import org.openidentity.auth.*;
import org.openidentity.delegation.*;
import org.openidentity.oauth.*;
import org.openidentity.spring.OpenIdentityExchange;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.*;
import java.io.StringReader;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

@Configuration
@ConditionalOnProperty(name="openidentity.live-wallet-exchange.enabled",havingValue="true")
public class LiveWalletExchangeConfiguration {
 static final HexFormat H=HexFormat.of();static final byte[] DOMAIN="openidentity:wallet:agent-grants:v1".getBytes(StandardCharsets.UTF_8);
 record Snapshot(byte[] root,byte[] rootHash,byte[] rootState,List<Agent> agents,List<Grant> grants){}
 record Agent(byte[] identity,byte[] publicKey,byte[] methodId,long generation,byte[] stateHash){}
 record Grant(byte[] id,byte[] rootHash,long generation,long registeredAt,byte[] profileHash,String capability){}
 static final class Client{
  final HttpClient http=HttpClient.newHttpClient();final String url=System.getenv().getOrDefault("OPENIDENTITY_WALLET_API_URL","http://127.0.0.1:9300")+"/v1/oauth/resolver";final String token=require("OPENIDENTITY_WALLET_API_TOKEN");
  Snapshot get(){try{var req=HttpRequest.newBuilder(URI.create(url)).header("Authorization","Bearer "+token).GET().build();var res=http.send(req,HttpResponse.BodyHandlers.ofString());if(res.statusCode()!=200)throw new IllegalStateException("wallet resolver HTTP "+res.statusCode());Properties p=new Properties();p.load(new StringReader(res.body()));List<Agent> agents=new ArrayList<>();for(int i=0;i<Integer.parseInt(p.getProperty("agent.count","0"));i++){String x="agent."+i+".";agents.add(new Agent(H.parseHex(p.getProperty(x+"identity")),H.parseHex(p.getProperty(x+"publicKey")),H.parseHex(p.getProperty(x+"authenticationMethodId")),Long.parseLong(p.getProperty(x+"authenticationGeneration")),H.parseHex(p.getProperty(x+"authenticationStateHash"))));}List<Grant> grants=new ArrayList<>();for(int i=0;i<Integer.parseInt(p.getProperty("grant.count","0"));i++){String x="grant."+i+".";grants.add(new Grant(H.parseHex(p.getProperty(x+"id")),H.parseHex(p.getProperty(x+"rootStateHash")),Long.parseLong(p.getProperty(x+"delegationGeneration")),Long.parseLong(p.getProperty(x+"registeredAt")),H.parseHex(p.getProperty(x+"profileHash")),p.getProperty(x+"capability")));}return new Snapshot(H.parseHex(p.getProperty("root.identity")),H.parseHex(p.getProperty("root.stateHash")),H.parseHex(p.getProperty("root.stateBytes")),agents,grants);}catch(Exception e){throw new IllegalStateException("live wallet resolver failed",e);}}
  static String require(String n){String v=System.getenv(n);if(v==null||v.isBlank())throw new IllegalStateException(n+" required");return v;}
 }
 @Bean @Primary DelegatedAgentExchangeService liveWalletExchange(){
  Client c=new Client();
  RegisteredGrantStateResolver records=(domain,id)->{Snapshot s=c.get();for(Grant g:s.grants)if(Arrays.equals(g.id,id)&&Arrays.equals(domain,DOMAIN))return new RegisteredGrantState(DOMAIN,g.id,1,RegisteredGrantState.ACTIVE,g.rootHash,g.generation,g.registeredAt);return null;};
  RootDelegationStateResolver roots=id->{Snapshot s=c.get();if(!Arrays.equals(id,s.root))return null;return new RootDelegationState(s.root,s.rootHash,true,generation(s.rootState));};
  CapabilityProfileResolver profiles=ph->{Snapshot s=c.get();for(Grant g:s.grants)if(Arrays.equals(ph,g.profileHash))return new P(g.profileHash,g.capability);return null;};
  AuthenticationStateResolver auth=id->{Snapshot s=c.get();for(Agent a:s.agents)if(Arrays.equals(id,a.identity))return new CurrentAuthenticationState(a.identity,a.stateHash,true,new AuthenticationPolicySnapshot(a.generation,1,List.of(new AuthenticationMethod(a.methodId,a.publicKey))));return null;};
  var oi016=new Oi016DelegatedSubjectVerifier(new Oi016Verifier(new DefaultOi014GrantVerifier(records,roots,profiles),profiles),()->Instant.now().getEpochSecond());
  var oi015=new Oi015AuthenticationAssertionVerifier(new Oi015Verifier(auth,300));
  CapabilityMapper mapper=(subject,target,scope)->target.equals("https://api.example.test/")&&subject.effectiveCapabilities().stream().anyMatch(x->x instanceof CapabilityRef cr&&scope.equals(new String(cr.capabilityId(),StandardCharsets.UTF_8)));
  Set<String> used=Collections.synchronizedSet(new HashSet<>());
  return new DelegatedAgentExchangeService(oi016,oi015,x->x,mapper,id->used.add(H.formatHex(id)),300);
 }
 @Bean @Primary OpenIdentityExchange liveWalletOpenIdentityExchange(DelegatedAgentExchangeService liveWalletExchange){return liveWalletExchange::exchange;}
 @Bean @Primary org.openidentity.spring.ActorNonceResolver liveWalletNonce(){return request->request.getParameter("openidentity_actor_nonce")==null?new byte[32]:Base64.getUrlDecoder().decode(request.getParameter("openidentity_actor_nonce"));}
 static long generation(byte[] state){org.openidentity.cbor.StrictCborReader r=new org.openidentity.cbor.StrictCborReader(state);long n=r.readMapHeader();for(long i=0;i<n;i++){long k=r.readUnsigned();if(k==9){var a=new org.openidentity.cbor.StrictCborReader(r.readEncoded());a.readMapHeader();a.readUnsigned();return a.readUnsigned();}r.skipValue();}throw new IllegalArgumentException("delegation authority unavailable");}
 record P(byte[] profileHash,String cap)implements CapabilityProfile{public long maximumGrantLifetimeSeconds(){return 86400;}public int maximumDelegationDepth(){return 1;}public boolean permitsChild(List<CapabilityRef>a,List<CapabilityRef>b){return false;}public List<Object> effectiveCapabilities(List<CapabilityRef> refs){for(CapabilityRef r:refs)if(!cap.equals(new String(r.capabilityId(),StandardCharsets.UTF_8)))throw new IllegalArgumentException("unsupported capability");return new ArrayList<>(refs);}}
}