package org.openidentity.protocol.v2;

import java.security.MessageDigest;
import java.util.*;
import org.openidentity.cbor.StrictCborReader;

record IdentityStateCommitment(
    int stateVersion,
    byte[] identity,
    long sequence,
    int status,
    byte[] stateHash,
    byte[] stateBytes) {
  public IdentityStateCommitment {
    identity = identity.clone();
    stateHash = stateHash.clone();
    stateBytes = stateBytes.clone();
    if (identity.length != 32 || stateHash.length != 34)
      throw new IllegalArgumentException("identity state commitment");
  }

  @Override
  public byte[] identity() {
    return identity.clone();
  }

  @Override
  public byte[] stateHash() {
    return stateHash.clone();
  }

  @Override
  public byte[] stateBytes() {
    return stateBytes.clone();
  }

  public static IdentityStateCommitment parse(byte[] stateBytes) {
    Objects.requireNonNull(stateBytes);
    StrictCborReader r = new StrictCborReader(stateBytes);
    long fields = r.readMapHeader();
    Integer version = null, status = null;
    Long sequence = null;
    byte[] identity = null;
    long previous = 0;
    for (long i = 0; i < fields; i++) {
      long key = r.readUnsigned();
      if (key <= previous)
        throw new IllegalArgumentException("IdentityState labels not strictly increasing");
      previous = key;
      if (key == 1) version = Math.toIntExact(r.readUnsigned());
      else if (key == 2) identity = r.readByteString();
      else if (key == 3) sequence = r.readUnsigned();
      else if (key == 4) status = Math.toIntExact(r.readUnsigned());
      else skip(r);
    }
    if (!r.done() || version == null || identity == null || sequence == null || status == null)
      throw new IllegalArgumentException("incomplete IdentityState");
    return new IdentityStateCommitment(
        version, identity, sequence, status, sha256Multihash(stateBytes), stateBytes);
  }

  public static byte[] sha256Multihash(byte[] bytes) {
    try {
      byte[] d = MessageDigest.getInstance("SHA-256").digest(bytes), out = new byte[34];
      out[0] = 0x12;
      out[1] = 0x20;
      System.arraycopy(d, 0, out, 2, 32);
      return out;
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static void skip(StrictCborReader r) {
    int b = r.peekByte(), major = b >>> 5;
    if (major == 0) {
      r.readUnsigned();
      return;
    }
    if (major == 1) {
      r.readNegative();
      return;
    }
    if (major == 2) {
      r.readByteString();
      return;
    }
    if (major == 3) {
      r.readTextString();
      return;
    }
    if (major == 4) {
      long n = r.readArrayHeader();
      for (long i = 0; i < n; i++) skip(r);
      return;
    }
    if (major == 5) {
      long n = r.readMapHeader();
      for (long i = 0; i < n; i++) {
        skip(r);
        skip(r);
      }
      return;
    }
    if (b == 0xf6) {
      r.readNull();
      return;
    }
    throw new IllegalArgumentException("unsupported IdentityState CBOR");
  }
}
