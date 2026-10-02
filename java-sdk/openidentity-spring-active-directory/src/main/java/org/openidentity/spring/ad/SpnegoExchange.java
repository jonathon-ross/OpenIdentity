package org.openidentity.spring.ad;
public interface SpnegoExchange extends AutoCloseable {
 Result accept(byte[] token);
 @Override void close();
 record Result(boolean established,String principal,byte[] responseToken){
  public Result{responseToken=responseToken==null?new byte[0]:responseToken.clone();}
  @Override public byte[] responseToken(){return responseToken.clone();}
 }
}