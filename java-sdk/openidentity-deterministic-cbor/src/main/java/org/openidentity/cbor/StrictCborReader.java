package org.openidentity.cbor;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class StrictCborReader {
 private final byte[] in;private int p;
 public StrictCborReader(byte[] in){this.in=in.clone();}
 public boolean done(){return p==in.length;}
 public int position(){return p;}
 public long readUnsigned(){Head h=head(0);return h.value;}
 public long readArrayHeader(){return head(4).value;}
 public long readMapHeader(){return head(5).value;}
 public byte[] readByteString(){Head h=head(2);int n=size(h.value);need(n);byte[] b=Arrays.copyOfRange(in,p,p+n);p+=n;return b;}
 public String readTextString(){return new String(readRawText(),StandardCharsets.UTF_8);}
 public byte[] readRawText(){Head h=head(3);int n=size(h.value);need(n);byte[] b=Arrays.copyOfRange(in,p,p+n);p+=n;return b;}
 public byte[] slice(int start,int end){return Arrays.copyOfRange(in,start,end);}
 private record Head(int ai,long value){}
 private Head head(int major){
  need(1);int b=in[p++]&255,m=b>>>5,ai=b&31;if(m!=major)throw new IllegalArgumentException("CBOR major type");
  if(ai<24)return new Head(ai,ai);
  if(ai==24){need(1);long v=in[p++]&255;if(v<24)throw new IllegalArgumentException("noncanonical CBOR integer");return new Head(ai,v);}
  if(ai==25){long v=readN(2);if(v<=255)throw new IllegalArgumentException("noncanonical CBOR integer");return new Head(ai,v);}
  if(ai==26){long v=readN(4);if(v<=65535)throw new IllegalArgumentException("noncanonical CBOR integer");return new Head(ai,v);}
  if(ai==27){long v=readN(8);if(v<0||v<=0xffffffffL)throw new IllegalArgumentException("noncanonical/unsupported CBOR integer");return new Head(ai,v);}
  throw new IllegalArgumentException("indefinite/reserved CBOR");
 }
 private long readN(int n){need(n);long v=0;for(int i=0;i<n;i++)v=(v<<8)|(in[p++]&255L);return v;}
 private int size(long n){if(n>Integer.MAX_VALUE)throw new IllegalArgumentException("CBOR length");return(int)n;}
 private void need(int n){if(n<0||p+n>in.length)throw new IllegalArgumentException("truncated CBOR");}
}
