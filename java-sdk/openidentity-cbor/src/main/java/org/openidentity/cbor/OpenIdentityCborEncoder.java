package org.openidentity.cbor;

import org.openidentity.core.*;

public final class OpenIdentityCborEncoder {
  private OpenIdentityCborEncoder() {}

  public static byte[] encodeState(IdentityState state) {
    if (state instanceof IdentityStateV1 v1) return encodeState(v1);
    if (state instanceof IdentityStateV2 v2) return encodeState(v2);
    throw new IllegalArgumentException("Unsupported IdentityState implementation");
  }

  public static byte[] encodeState(IdentityStateV1 state) {
    DeterministicCbor c = new DeterministicCbor();
    c.map(state.recoveryCommitment() == null ? 5 : 6);
    c.integer(1);
    c.integer(1);
    c.integer(2);
    c.bytes(state.identity().bytes());
    c.integer(3);
    c.unsigned(state.sequence().value());
    c.integer(4);
    c.integer(state.status().code());
    c.integer(5);
    encodePolicy(c, state.controllerPolicy());
    if (state.recoveryCommitment() != null) {
      c.integer(6);
      c.bytes(state.recoveryCommitment().bytes());
    }
    return c.toByteArray();
  }

  public static byte[] encodeState(IdentityStateV2 state) {
    DeterministicCbor c = new DeterministicCbor();
    int fields = 5;
    if (state.recoveryCommitment() != null) fields++;
    if (state.assertionPolicy() != null) fields++;
    c.map(fields);
    c.integer(1);
    c.integer(2);
    c.integer(2);
    c.bytes(state.identity().bytes());
    c.integer(3);
    c.unsigned(state.sequence().value());
    c.integer(4);
    c.integer(state.status().code());
    c.integer(5);
    encodePolicy(c, state.controllerPolicy());
    if (state.recoveryCommitment() != null) {
      c.integer(6);
      c.bytes(state.recoveryCommitment().bytes());
    }
    if (state.assertionPolicy() != null) {
      c.integer(7);
      encodePolicy(c, state.assertionPolicy());
    }
    return c.toByteArray();
  }

  public static byte[] encodeOperationSigningInput(
      String domain, int signingStructureVersion, byte[] operationBytes) {
    if (domain == null) throw new NullPointerException("domain");
    if (operationBytes == null) throw new NullPointerException("operationBytes");
    DeterministicCbor c = new DeterministicCbor();
    c.array(3);
    c.text(domain);
    c.integer(signingStructureVersion);
    c.bytes(operationBytes);
    return c.toByteArray();
  }

  public static byte[] encodeMethodSigningInput(
      String domain, int signingStructureVersion, byte[] operationBytes, byte[] methodId) {
    if (domain == null) throw new NullPointerException("domain");
    if (operationBytes == null) throw new NullPointerException("operationBytes");
    if (methodId == null) throw new NullPointerException("methodId");
    DeterministicCbor c = new DeterministicCbor();
    c.array(4);
    c.text(domain);
    c.integer(signingStructureVersion);
    c.bytes(operationBytes);
    c.bytes(methodId);
    return c.toByteArray();
  }

  public static byte[] encodeCreateOperation(
      IdentityId identity, ControllerPolicy policy, RecoveryCommitment recoveryCommitment) {
    DeterministicCbor c = new DeterministicCbor();
    c.map(6);
    c.integer(1);
    c.integer(1);
    c.integer(2);
    c.integer(1);
    c.integer(3);
    c.bytes(identity.bytes());
    c.integer(4);
    c.integer(1);
    c.integer(5);
    c.nil();
    c.integer(6);
    c.map(recoveryCommitment == null ? 1 : 2);
    c.integer(1);
    encodePolicy(c, policy);
    if (recoveryCommitment != null) {
      c.integer(2);
      c.bytes(recoveryCommitment.bytes());
    }
    return c.toByteArray();
  }

  public static byte[] encodeRotateControllerOperation(
      IdentityId identity,
      Sequence sequence,
      StateHash previousStateHash,
      ControllerPolicy proposedPolicy) {
    DeterministicCbor c = new DeterministicCbor();
    c.map(6);
    c.integer(1);
    c.integer(1);
    c.integer(2);
    c.integer(2);
    c.integer(3);
    c.bytes(identity.bytes());
    c.integer(4);
    c.unsigned(sequence.value());
    c.integer(5);
    c.bytes(previousStateHash.bytes());
    c.integer(6);
    c.map(1);
    c.integer(1);
    encodePolicy(c, proposedPolicy);
    return c.toByteArray();
  }

  public static byte[] encodeSetAssertionPolicyOperation(
      IdentityId identity,
      Sequence sequence,
      StateHash previousStateHash,
      AssertionPolicy assertionPolicy) {
    DeterministicCbor c = new DeterministicCbor();
    c.map(6);
    c.integer(1);
    c.integer(1);
    c.integer(2);
    c.integer(5);
    c.integer(3);
    c.bytes(identity.bytes());
    c.integer(4);
    c.unsigned(sequence.value());
    c.integer(5);
    c.bytes(previousStateHash.bytes());
    c.integer(6);
    c.map(1);
    c.integer(1);
    if (assertionPolicy == null) c.nil();
    else encodePolicy(c, assertionPolicy);
    return c.toByteArray();
  }

  public static byte[] encodeDeactivateOperation(
      IdentityId identity, Sequence sequence, StateHash previousStateHash) {
    DeterministicCbor c = new DeterministicCbor();
    c.map(6);
    c.integer(1);
    c.integer(1);
    c.integer(2);
    c.integer(4);
    c.integer(3);
    c.bytes(identity.bytes());
    c.integer(4);
    c.unsigned(sequence.value());
    c.integer(5);
    c.bytes(previousStateHash.bytes());
    c.integer(6);
    c.map(0);
    return c.toByteArray();
  }

  public static byte[] encodeRecoveryPolicy(RecoveryPolicy policy) {
    DeterministicCbor c = new DeterministicCbor();
    encodeRecoveryPolicy(c, policy);
    return c.toByteArray();
  }

  public static byte[] encodeRecoverOperation(
      IdentityId identity,
      Sequence sequence,
      StateHash previousStateHash,
      ControllerPolicy newControllerPolicy,
      RecoveryPolicy currentRecoveryPolicy,
      RecoveryCommitment newRecoveryCommitment) {
    DeterministicCbor c = new DeterministicCbor();
    c.map(6);
    c.integer(1);
    c.integer(1);
    c.integer(2);
    c.integer(3);
    c.integer(3);
    c.bytes(identity.bytes());
    c.integer(4);
    c.unsigned(sequence.value());
    c.integer(5);
    c.bytes(previousStateHash.bytes());
    c.integer(6);
    c.map(3);
    c.integer(1);
    encodePolicy(c, newControllerPolicy);
    c.integer(2);
    encodeRecoveryPolicy(c, currentRecoveryPolicy);
    c.integer(3);
    c.bytes(newRecoveryCommitment.bytes());
    return c.toByteArray();
  }

  private static void encodeRecoveryPolicy(DeterministicCbor c, RecoveryPolicy policy) {
    if (policy.isSingle()) {
      c.map(3);
      c.integer(1);
      c.integer(1);
      c.integer(2);
      c.integer(1);
      c.integer(3);
      c.array(1);
      encodeMethod(c, policy.methods().get(0));
    } else {
      c.map(4);
      c.integer(1);
      c.integer(1);
      c.integer(2);
      c.integer(2);
      c.integer(3);
      c.integer(policy.threshold());
      c.integer(4);
      c.array(policy.methods().size());
      for (VerificationMethod m : policy.methods()) encodeMethod(c, m);
    }
  }

  public static byte[] encodeCredential(
      byte[] credentialId,
      IdentityId issuer,
      StateHash issuanceStateHash,
      long validFrom,
      Long validUntil,
      String profile,
      byte[] subject,
      java.util.Map<String, Object> claims) {
    DeterministicCbor c = new DeterministicCbor();
    c.map(validUntil == null ? 8 : 9);
    c.integer(1);
    c.integer(1);
    c.integer(2);
    c.bytes(credentialId);
    c.integer(3);
    c.bytes(issuer.bytes());
    c.integer(4);
    c.bytes(issuanceStateHash.bytes());
    c.integer(5);
    c.unsigned(java.math.BigInteger.valueOf(validFrom));
    if (validUntil != null) {
      c.integer(6);
      c.unsigned(java.math.BigInteger.valueOf(validUntil));
    }
    c.integer(7);
    c.text(profile);
    c.integer(8);
    c.bytes(subject);
    c.integer(9);
    encodeClaimMap(c, claims);
    return c.toByteArray();
  }

  private static void encodeClaimMap(DeterministicCbor c, java.util.Map<String, Object> map) {
    java.util.List<java.util.Map.Entry<String, Object>> entries =
        new java.util.ArrayList<>(map.entrySet());
    entries.sort((a, b) -> compareCborTextKeys(a.getKey(), b.getKey()));
    c.map(entries.size());
    for (var e : entries) {
      c.text(e.getKey());
      encodeClaimValue(c, e.getValue());
    }
  }

  private static int compareCborTextKeys(String a, String b) {
    byte[] x = a.getBytes(java.nio.charset.StandardCharsets.UTF_8),
        y = b.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    int hx = x.length < 24 ? 1 : x.length <= 255 ? 2 : x.length <= 65535 ? 3 : 5,
        hy = y.length < 24 ? 1 : y.length <= 255 ? 2 : y.length <= 65535 ? 3 : 5;
    int lx = hx + x.length, ly = hy + y.length;
    if (lx != ly) return Integer.compare(lx, ly);
    for (int i = 0; i < Math.min(x.length, y.length); i++) {
      int d = Integer.compare(x[i] & 255, y[i] & 255);
      if (d != 0) return d;
    }
    return Integer.compare(x.length, y.length);
  }

  @SuppressWarnings("unchecked")
  private static void encodeClaimValue(DeterministicCbor c, Object v) {
    if (v == null) {
      c.nil();
      return;
    }
    if (v instanceof String s) {
      c.text(s);
      return;
    }
    if (v instanceof byte[] b) {
      c.bytes(b);
      return;
    }
    if (v instanceof Boolean b) {
      c.bool(b);
      return;
    }
    if (v instanceof Byte
        || v instanceof Short
        || v instanceof Integer
        || v instanceof Long
        || v instanceof java.math.BigInteger) {
      java.math.BigInteger n =
          v instanceof java.math.BigInteger bi
              ? bi
              : java.math.BigInteger.valueOf(((Number) v).longValue());
      c.number(n);
      return;
    }
    if (v instanceof java.util.List<?> a) {
      c.array(a.size());
      for (Object x : a) encodeClaimValue(c, x);
      return;
    }
    if (v instanceof java.util.Map<?, ?> m) {
      java.util.Map<String, Object> s = new java.util.HashMap<>();
      for (var e : m.entrySet()) {
        if (!(e.getKey() instanceof String k))
          throw new IllegalArgumentException("Claim map keys must be text");
        s.put(k, e.getValue());
      }
      encodeClaimMap(c, s);
      return;
    }
    throw new IllegalArgumentException(
        "Unsupported credential claim value: " + v.getClass().getName());
  }

  public static byte[] encodeCredentialSigningInput(byte[] credentialBytes) {
    DeterministicCbor c = new DeterministicCbor();
    c.array(3);
    c.text("OpenIdentity Credential");
    c.integer(1);
    c.bytes(credentialBytes);
    return c.toByteArray();
  }

  public static byte[] encodeSignatureProof(byte[] methodId, byte[] signature) {
    if (methodId == null) throw new NullPointerException("methodId");
    if (signature == null) throw new NullPointerException("signature");
    DeterministicCbor c = new DeterministicCbor();
    c.map(2);
    c.integer(1);
    c.bytes(methodId);
    c.integer(2);
    c.bytes(signature);
    return c.toByteArray();
  }

  public static byte[] encodeControllerPolicy(ControllerPolicy policy) {
    DeterministicCbor c = new DeterministicCbor();
    encodePolicy(c, policy);
    return c.toByteArray();
  }

  public static byte[] encodeVerificationMethod(VerificationMethod method) {
    DeterministicCbor c = new DeterministicCbor();
    encodeMethod(c, method);
    return c.toByteArray();
  }

  private static void encodePolicy(DeterministicCbor c, AuthorityPolicy policy) {
    if (policy.isSingle()) {
      c.map(2);
      c.integer(1);
      c.integer(1);
      c.integer(2);
      c.array(1);
      encodeMethod(c, policy.methods().getFirst());
    } else {
      c.map(3);
      c.integer(1);
      c.integer(2);
      c.integer(2);
      c.integer(policy.threshold());
      c.integer(3);
      c.array(policy.methods().size());
      for (VerificationMethod method : policy.methods()) encodeMethod(c, method);
    }
  }

  private static void encodeMethod(DeterministicCbor c, VerificationMethod method) {
    c.map(2);
    c.integer(1);
    c.bytes(method.id().bytes());
    c.integer(2);
    CoseKey material = method.key();
    if (material instanceof Ed25519Key ed) {
      c.map(4);
      c.integer(1);
      c.integer(1);
      c.integer(3);
      c.integer(-8);
      c.integer(-1);
      c.integer(6);
      c.integer(-2);
      c.bytes(ed.publicKey());
    } else if (material instanceof MlDsa65Key ml) {
      c.map(3);
      c.integer(1);
      c.integer(7);
      c.integer(3);
      c.integer(-49);
      c.integer(-1);
      c.bytes(ml.publicKey());
    } else throw new IllegalArgumentException("Unsupported v0.1 method material");
  }
}
