package org.openidentity.cbor;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public final class DeterministicCborWriter {
    private final ByteArrayOutputStream out=new ByteArrayOutputStream();
    public byte[] toByteArray(){return out.toByteArray();}
    public void writeUnsigned(long v){if(v<0)throw new IllegalArgumentException("unsigned value");writeType(0,v);}
    public void writeByteString(byte[] v){Objects.requireNonNull(v,"value");writeType(2,v.length);out.writeBytes(v);}
    public void writeTextString(String v){Objects.requireNonNull(v,"value");byte[] b=v.getBytes(StandardCharsets.UTF_8);writeType(3,b.length);out.writeBytes(b);}
    public void writeArrayHeader(int n){if(n<0)throw new IllegalArgumentException("array size");writeType(4,n);}
    public void writeMapHeader(int n){if(n<0)throw new IllegalArgumentException("map size");writeType(5,n);}
    public void writeEncoded(byte[] encodedCbor){Objects.requireNonNull(encodedCbor,"encodedCbor");out.writeBytes(encodedCbor);}
    private void writeType(int major,long v){int p=major<<5;if(v<=23)out.write(p|(int)v);else if(v<=0xff){out.write(p|24);out.write((int)v);}else if(v<=0xffff){out.write(p|25);be(v,2);}else if(v<=0xffffffffL){out.write(p|26);be(v,4);}else{out.write(p|27);be(v,8);}}
    private void be(long v,int n){for(int i=n-1;i>=0;i--)out.write((int)(v>>>(i*8))&255);}
}
