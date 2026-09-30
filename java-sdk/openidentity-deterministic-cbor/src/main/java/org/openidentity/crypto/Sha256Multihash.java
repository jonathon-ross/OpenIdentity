package org.openidentity.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public final class Sha256Multihash {
    public static final int LENGTH=34;
    private Sha256Multihash(){}
    public static byte[] digest(byte[] input){
        try{byte[] d=MessageDigest.getInstance("SHA-256").digest(input);byte[] out=new byte[LENGTH];out[0]=0x12;out[1]=0x20;System.arraycopy(d,0,out,2,d.length);return out;}
        catch(NoSuchAlgorithmException e){throw new IllegalStateException("SHA-256 unavailable",e);}
    }
    public static byte[] requireValid(byte[] value){
        if(value==null||value.length!=LENGTH||value[0]!=0x12||value[1]!=0x20)throw new IllegalArgumentException("Expected SHA2-256 Multihash");
        return Arrays.copyOf(value,value.length);
    }
}
