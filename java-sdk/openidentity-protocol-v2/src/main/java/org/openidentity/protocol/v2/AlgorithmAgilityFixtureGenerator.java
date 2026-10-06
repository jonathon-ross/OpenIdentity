package org.openidentity.protocol.v2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.*;

public final class AlgorithmAgilityFixtureGenerator {
 private static final ObjectMapper JSON=new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
 private static final String PREFIX="OpenIdentity agility-v1 ";
 private static final byte[] OPERATION=hex("a601020206035820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f04020558221220999a1ef498ae077a6d4835129e889a8a3392ec887b8a3b2bf4612874fb511c9606a0");
 private AlgorithmAgilityFixtureGenerator(){}

 record Ml(byte[] seed, MLDSAPrivateKey sk, MLDSAPublicKey pk){}
 record Ed(byte[] seed, Ed25519PrivateKeyParameters sk, Ed25519PublicKeyParameters pk){}

 public static void main(String[] args)throws Exception{
  Security.addProvider(new BouncyCastleProvider());
  Path out=args.length==0?Path.of("../../test-vectors/generated/algorithm-agility-v1.json"):Path.of(args[0]);
  List<Map<String,Object>> valid=new ArrayList<>(),invalid=new ArrayList<>();

  Ml controller=ml("ML02","controller");
  Ml pop=ml("ML05","controller-pop");
  Ml recovery=ml("ML06","recovery");
  Ml auth=ml("ML07","authentication");
  Ml assertion=ml("ML08","assertion");
  Ml delegation=ml("ML09","delegation");
  Ed mixedEd=ed("ML03","ed25519");
  Ml mixedMl=ml("ML03","ml-dsa-65");

  valid.add(single("ML01","Ed25519 SINGLE controller authorization",ed("ML01","controller"),controllerAuth()));
  valid.add(single("ML02","ML-DSA-65 SINGLE controller authorization",controller,controllerAuth()));
  valid.add(mixed("ML03","mixed Ed25519 + ML-DSA-65 threshold 2-of-2",2,mixedEd,mixedMl,controllerAuth()));
  valid.add(mixed("ML04","mixed Ed25519 + ML-DSA-65 threshold 1-of-2",1,ed("ML04","ed25519"),ml("ML04","ml-dsa-65"),controllerAuth()));
  valid.add(single("ML05","ML-DSA-65 Controller proof of possession",pop,popBytes("OpenIdentity Controller Proof",method("ML05","controller-pop"))));
  valid.add(single("ML06","ML-DSA-65 Recovery authorization",recovery,popBytes("OpenIdentity Recovery",method("ML06","recovery"))));
  valid.add(single("ML07","ML-DSA-65 Authentication proof of possession",auth,popBytes("OpenIdentity Authentication Proof",method("ML07","authentication"))));
  valid.add(single("ML08","ML-DSA-65 Assertion proof of possession",assertion,popBytes("OpenIdentity Assertion Proof",method("ML08","assertion"))));
  valid.add(single("ML09","ML-DSA-65 Delegation proof of possession",delegation,popBytes("OpenIdentity Delegation Proof",method("ML09","delegation"))));

  Map<String,Object> base=single("MLI01","wrong ML-DSA-65 signature",ml("MLI01","key"),controllerAuth());
  byte[] bad=hex((String)base.get("signatureHex"));bad[0]^=1;base.put("signatureHex",HexFormat.of().formatHex(bad));base.put("expected","REJECT");base.put("expectedError","INVALID_SIGNATURE");invalid.add(base);
  invalid.add(wrongDomain("MLI02"));
  invalid.add(wrongMethod("MLI03"));
  invalid.add(truncated("MLI04"));
  invalid.add(Map.of("id","MLI05","expected","REJECT","expectedError","MALFORMED_COSE_KEY","algorithm","ML-DSA-65","publicKeyHex","00".repeat(1951)));
  Map<String,Object> insufficient=mixed("MLI06","mixed threshold not satisfied",2,ed("MLI06","ed25519"),ml("MLI06","ml-dsa-65"),controllerAuth());insufficient.put("expected","REJECT");insufficient.put("expectedError","INSUFFICIENT_THRESHOLD");((List<?>)insufficient.get("proofs")).remove(1);invalid.add(insufficient);
  Ml dup=ml("MLI07","duplicate");invalid.add(Map.of("id","MLI07","expected","REJECT","expectedError","DUPLICATE_EFFECTIVE_VERIFICATION_KEY","methodId1Hex",hx(method("MLI07","one")),"methodId2Hex",hx(method("MLI07","two")),"publicKeyHex",hx(raw(dup))));
  invalid.add(Map.of("id","MLI08","expected","REJECT","expectedError","ALGORITHM_KEY_MISMATCH","declaredAlgorithm","Ed25519","actualAlgorithm","ML-DSA-65","publicKeyHex",hx(raw(ml("MLI08","key")))));

  Map<String,Object> root=new LinkedHashMap<>();
  root.put("specification","OpenIdentity cryptographic agility v1");root.put("status","DRAFT-NON-NORMATIVE");root.put("normativeCrypto","FIPS 204 ML-DSA-65");
  root.put("mlDsa65",Map.of("publicKeyBytes",1952,"signatureBytes",3309));
  root.put("generationProfile",Map.of("seedBytes",32,"seedDerivation","SHA-256(UTF-8('OpenIdentity agility-v1 ' || vector-id || ' ' || role))","privateMaterialPersisted",false,"provider","Bouncy Castle 1.86"));
  root.put("operationBytesHex",hx(OPERATION));root.put("validVectors",valid);root.put("invalidVectors",invalid);
  Files.createDirectories(out.toAbsolutePath().getParent());JSON.writeValue(out.toFile(),root);
  System.out.println("OPENIDENTITY ALGORITHM AGILITY V1: GENERATED");
  System.out.println("Valid: "+valid.size()+" Invalid: "+invalid.size());
  System.out.println("ML-DSA-65 public key bytes: 1952");
  System.out.println("ML-DSA-65 signature bytes: 3309");
  System.out.println(out.toAbsolutePath());
 }
 static Ml ml(String id,String role)throws Exception{
  byte[] seed=seed(id,role);KeyFactory kf=KeyFactory.getInstance("ML-DSA-65","BC");KeySpec spec=new MLDSAPrivateKeySpec(MLDSAParameterSpec.ml_dsa_65,seed);
  MLDSAPrivateKey sk=(MLDSAPrivateKey)kf.generatePrivate(spec);MLDSAPublicKey pk=sk.getPublicKey();
  if(pk.getPublicData().length!=1952)throw new IllegalStateException("ML-DSA-65 public key length");
  return new Ml(seed,sk,pk);
 }
 static Ed ed(String id,String role)throws Exception{byte[] s=seed(id,role);var sk=new Ed25519PrivateKeyParameters(s,0);return new Ed(s,sk,sk.generatePublicKey());}
 static byte[] raw(Ml x){return x.pk.getPublicData();}
 static byte[] sign(Ml x,byte[] msg)throws Exception{Signature s=Signature.getInstance("ML-DSA-65","BC");s.initSign(x.sk);s.update(msg);byte[] sig=s.sign();if(sig.length!=3309)throw new IllegalStateException("ML-DSA-65 signature length");s.initVerify(x.pk);s.update(msg);if(!s.verify(sig))throw new IllegalStateException("ML-DSA self verify");return sig;}
 static byte[] sign(Ed x,byte[] msg){var s=new Ed25519Signer();s.init(true,x.sk);s.update(msg,0,msg.length);byte[] sig=s.generateSignature();var v=new Ed25519Signer();v.init(false,x.pk);v.update(msg,0,msg.length);if(!v.verifySignature(sig))throw new IllegalStateException("Ed25519 self verify");return sig;}
 static Map<String,Object> single(String id,String purpose,Ml k,byte[] msg)throws Exception{var m=new LinkedHashMap<String,Object>();m.put("id",id);m.put("expected","PASS");m.put("purpose",purpose);m.put("algorithm","ML-DSA-65");m.put("methodIdHex",hx(method(id,purpose)));m.put("publicKeyHex",hx(raw(k)));m.put("signingBytesHex",hx(msg));m.put("signatureHex",hx(sign(k,msg)));return m;}
 static Map<String,Object> single(String id,String purpose,Ed k,byte[] msg){var m=new LinkedHashMap<String,Object>();m.put("id",id);m.put("expected","PASS");m.put("purpose",purpose);m.put("algorithm","Ed25519");m.put("methodIdHex",hx(method(id,purpose)));m.put("publicKeyHex",hx(k.pk.getEncoded()));m.put("signingBytesHex",hx(msg));m.put("signatureHex",hx(sign(k,msg)));return m;}
 static Map<String,Object> mixed(String id,String purpose,int threshold,Ed e,Ml m,byte[] msg)throws Exception{var x=new LinkedHashMap<String,Object>();x.put("id",id);x.put("expected","PASS");x.put("purpose",purpose);x.put("threshold",threshold);x.put("methods",List.of(Map.of("algorithm","Ed25519","methodIdHex",hx(method(id,"ed25519")),"publicKeyHex",hx(e.pk.getEncoded())),Map.of("algorithm","ML-DSA-65","methodIdHex",hx(method(id,"ml-dsa-65")),"publicKeyHex",hx(raw(m)))));x.put("signingBytesHex",hx(msg));x.put("proofs",new ArrayList<>(List.of(Map.of("algorithm","Ed25519","methodIdHex",hx(method(id,"ed25519")),"signatureHex",hx(sign(e,msg))),Map.of("algorithm","ML-DSA-65","methodIdHex",hx(method(id,"ml-dsa-65")),"signatureHex",hx(sign(m,msg))))));return x;}
 static Map<String,Object> wrongDomain(String id)throws Exception{Ml k=ml(id,"key");byte[] wrong=popBytes("OpenIdentity Assertion Proof",method(id,"key")),required=popBytes("OpenIdentity Authentication Proof",method(id,"key"));var x=single(id,"wrong signing domain",k,wrong);x.put("expected","REJECT");x.put("expectedError","INVALID_PROOF_OF_POSSESSION");x.put("sourceSigningBytesHex",hx(wrong));x.put("requiredSigningBytesHex",hx(required));return x;}
 static Map<String,Object> wrongMethod(String id)throws Exception{Ml k=ml(id,"key");byte[] authorized=method(id,"authorized"),wrong=method(id,"wrong"),msg=popBytes("OpenIdentity Authentication Proof",wrong);var x=single(id,"wrong VerificationMethod ID",k,msg);x.put("expected","REJECT");x.put("expectedError","UNAUTHORIZED_METHOD");x.put("authorizedMethodIdHex",hx(authorized));x.put("methodIdHex",hx(wrong));return x;}
 static Map<String,Object> truncated(String id)throws Exception{Ml k=ml(id,"key");byte[] msg=controllerAuth(),sig=sign(k,msg);var x=single(id,"truncated ML-DSA-65 signature",k,msg);x.put("expected","REJECT");x.put("expectedError","INVALID_SIGNATURE");x.put("signatureHex",hx(Arrays.copyOf(sig,sig.length-1)));return x;}
 static byte[] seed(String id,String role)throws Exception{return MessageDigest.getInstance("SHA-256").digest((PREFIX+id+" "+role).getBytes(StandardCharsets.UTF_8));}
 static byte[] method(String id,String role)throws Exception{return Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(("OpenIdentity method "+id+" "+role).getBytes(StandardCharsets.UTF_8)),16);}
 static byte[] controllerAuth(){return cbor("OpenIdentity Operation",null);}
 static byte[] popBytes(String domain,byte[] mid){return cbor(domain,mid);}
 static byte[] cbor(String domain,byte[] mid){try{var o=new ByteArrayOutputStream();o.write(mid==null?0x83:0x84);text(o,domain);o.write(0x01);bytes(o,OPERATION);if(mid!=null)bytes(o,mid);return o.toByteArray();}catch(Exception e){throw new RuntimeException(e);}}
 static void text(ByteArrayOutputStream o,String s){byte[] b=s.getBytes(StandardCharsets.UTF_8);if(b.length<24)o.write(0x60+b.length);else{o.write(0x78);o.write(b.length);}o.writeBytes(b);}
 static void bytes(ByteArrayOutputStream o,byte[] b){if(b.length<24)o.write(0x40+b.length);else if(b.length<=255){o.write(0x58);o.write(b.length);}else{o.write(0x59);o.write((b.length>>>8)&255);o.write(b.length&255);}o.writeBytes(b);}
 static String hx(byte[] b){return HexFormat.of().formatHex(b);}static byte[] hex(String s){return HexFormat.of().parseHex(s);}
}
