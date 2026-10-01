package org.openidentity.core;

import java.io.*;import java.nio.charset.StandardCharsets;import java.nio.file.*;import java.util.*;

public final class FileCanonicalIdentityStateRepository implements MutableCanonicalIdentityStateRepository {
 private final Path directory;
 public FileCanonicalIdentityStateRepository(Path directory){this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();}
 @Override public synchronized CanonicalIdentityState resolve(byte[] identity){
  Objects.requireNonNull(identity);if(identity.length!=32)throw new IllegalArgumentException("identity");
  Path p=file(identity);if(!Files.isRegularFile(p))return null;
  try{return decode(Files.readString(p,StandardCharsets.US_ASCII));}catch(IOException e){throw new UncheckedIOException(e);}
 }
 @Override public synchronized void save(CanonicalIdentityState state){
  Objects.requireNonNull(state);try{
   Files.createDirectories(directory);Path target=file(state.identity()),tmp=Files.createTempFile(directory,target.getFileName().toString(),".tmp");
   try{Files.writeString(tmp,encode(state),StandardCharsets.US_ASCII,StandardOpenOption.TRUNCATE_EXISTING);try{Files.move(tmp,target,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}catch(AtomicMoveNotSupportedException e){Files.move(tmp,target,StandardCopyOption.REPLACE_EXISTING);}}
   finally{Files.deleteIfExists(tmp);}
  }catch(IOException e){throw new UncheckedIOException(e);}
 }
 private Path file(byte[] id){return directory.resolve(HexFormat.of().formatHex(id)+".oidstate");}
 static String encode(CanonicalIdentityState s){
  StringBuilder b=new StringBuilder();var h=HexFormat.of();
  b.append("version=1\nidentity=").append(h.formatHex(s.identity())).append("\nstateHash=").append(h.formatHex(s.stateHash())).append("\nactive=").append(s.active()).append("\ngeneration=").append(s.authenticationAuthority().generation()).append("\nthreshold=").append(s.authenticationAuthority().threshold()).append("\nmethods=").append(s.authenticationAuthority().methods().size()).append("\n");
  for(int i=0;i<s.authenticationAuthority().methods().size();i++){var m=s.authenticationAuthority().methods().get(i);b.append("method.").append(i).append(".id=").append(h.formatHex(m.methodId())).append("\nmethod.").append(i).append(".ed25519=").append(h.formatHex(m.ed25519PublicKey())).append("\n");}
  return b.toString();
 }
 static CanonicalIdentityState decode(String text){
  Map<String,String> v=new LinkedHashMap<>();for(String line:text.split("\\R")){if(line.isEmpty())continue;int x=line.indexOf('=');if(x<1||v.put(line.substring(0,x),line.substring(x+1))!=null)throw new IllegalArgumentException("state file");}
  if(!"1".equals(v.get("version")))throw new IllegalArgumentException("version");var h=HexFormat.of();byte[] id=h.parseHex(req(v,"identity")),hash=h.parseHex(req(v,"stateHash"));boolean active=switch(req(v,"active")){case "true"->true;case "false"->false;default->throw new IllegalArgumentException("active");};
  long generation=Long.parseLong(req(v,"generation"));int threshold=Integer.parseInt(req(v,"threshold")),n=Integer.parseInt(req(v,"methods"));List<CanonicalAuthenticationMethod> methods=new ArrayList<>();
  for(int i=0;i<n;i++)methods.add(new CanonicalAuthenticationMethod(h.parseHex(req(v,"method."+i+".id")),h.parseHex(req(v,"method."+i+".ed25519"))));
  Set<String> expected=new HashSet<>(Set.of("version","identity","stateHash","active","generation","threshold","methods"));for(int i=0;i<n;i++){expected.add("method."+i+".id");expected.add("method."+i+".ed25519");}if(!v.keySet().equals(expected))throw new IllegalArgumentException("unexpected state field");
  return new CanonicalIdentityState(id,hash,active,new CanonicalAuthenticationAuthority(generation,threshold,methods));
 }
 private static String req(Map<String,String> v,String k){String x=v.get(k);if(x==null)throw new IllegalArgumentException("missing "+k);return x;}
}
