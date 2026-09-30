package org.openidentity.oauth;

import org.openidentity.cbor.DeterministicCborWriter;
import org.openidentity.crypto.Sha256Multihash;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class OAuthTokenExchangeContextV1Encoder {
    private OAuthTokenExchangeContextV1Encoder(){}
    public static byte[] encode(OAuthTokenExchangeContextV1 c){
        byte[] as=utf8(c.authorizationServer(),1,2048,"authorizationServer");requireAbsoluteUri(c.authorizationServer(),"authorizationServer");
        byte[] client=utf8(c.clientId(),1,512,"clientId");
        byte[] rt=null;if(c.requestedTokenType()!=null){rt=utf8(c.requestedTokenType(),1,2048,"requestedTokenType");requireAbsoluteUri(c.requestedTokenType(),"requestedTokenType");}
        List<byte[]> resources=canonical(c.resources(),16,2048,"resource",true);
        List<byte[]> audiences=canonical(c.audiences(),16,1024,"audience",false);
        List<byte[]> scopes=canonicalScopes(c.scopes());
        byte[] eid=Sha256Multihash.requireValid(c.delegationEvidenceId());
        byte[] jkt=utf8(c.dpopJkt(),43,43,"dpopJkt");if(!c.dpopJkt().matches("[A-Za-z0-9_-]{43}"))throw new IllegalArgumentException("invalid dpopJkt");
        DeterministicCborWriter w=new DeterministicCborWriter();w.writeMapHeader(rt==null?8:9);
        w.writeUnsigned(1);w.writeUnsigned(1);w.writeUnsigned(2);w.writeByteString(as);w.writeUnsigned(3);w.writeByteString(client);
        if(rt!=null){w.writeUnsigned(4);w.writeByteString(rt);}
        w.writeUnsigned(5);array(w,resources);w.writeUnsigned(6);array(w,audiences);w.writeUnsigned(7);array(w,scopes);
        w.writeUnsigned(8);w.writeByteString(eid);w.writeUnsigned(9);w.writeByteString(jkt);return w.toByteArray();
    }
    public static byte[] contextHash(OAuthTokenExchangeContextV1 c){return Sha256Multihash.digest(encode(c));}
    private static List<byte[]> canonical(List<String> values,int maxCount,int maxBytes,String name,boolean resource){
        if(values.size()>maxCount)throw new IllegalArgumentException("too many "+name+" values");List<byte[]> out=new ArrayList<>();
        for(String v:values){byte[] b=utf8(v,1,maxBytes,name);if(resource){URI u=requireAbsoluteUri(v,name);if(u.getFragment()!=null)throw new IllegalArgumentException("resource fragment");}out.add(b);}
        out.sort(Arrays::compareUnsigned);for(int i=1;i<out.size();i++)if(Arrays.equals(out.get(i-1),out.get(i)))throw new IllegalArgumentException("duplicate "+name);return List.copyOf(out);
    }
    private static List<byte[]> canonicalScopes(List<String> values){
        if(values.size()>64)throw new IllegalArgumentException("too many scopes");List<byte[]> out=new ArrayList<>();
        for(String v:values){byte[] b=utf8(v,1,256,"scope");for(byte x:b){int q=x&255;if(!(q==0x21||(q>=0x23&&q<=0x5b)||(q>=0x5d&&q<=0x7e)))throw new IllegalArgumentException("invalid scope");}out.add(b);}
        out.sort(Arrays::compareUnsigned);for(int i=1;i<out.size();i++)if(Arrays.equals(out.get(i-1),out.get(i)))throw new IllegalArgumentException("duplicate scope");return List.copyOf(out);
    }
    private static byte[] utf8(String s,int min,int max,String name){byte[] b=Objects.requireNonNull(s,name).getBytes(StandardCharsets.UTF_8);if(b.length<min||b.length>max)throw new IllegalArgumentException(name+" length");return b;}
    private static URI requireAbsoluteUri(String s,String name){URI u;try{u=URI.create(s);}catch(IllegalArgumentException e){throw new IllegalArgumentException(name+" URI",e);}if(!u.isAbsolute())throw new IllegalArgumentException(name+" must be absolute URI");return u;}
    private static void array(DeterministicCborWriter w,List<byte[]> xs){w.writeArrayHeader(xs.size());for(byte[] x:xs)w.writeByteString(x);}
}
