package org.openidentity.cbor;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.openidentity.core.*;

/** Decodes canonical OpenIdentity protocol structures from deterministic CBOR. */
public final class OpenIdentityCborDecoder {
  private OpenIdentityCborDecoder() {}

  /**
   * Decodes an IdentityState v1 or v2.
   *
   * @param bytes complete encoded state
   * @return immutable decoded state
   * @throws IllegalArgumentException for malformed, trailing, unsupported, or invalid protocol data
   */
  public static IdentityState decodeState(byte[] bytes) {
    CborReader reader = new CborReader(bytes);
    Object root = reader.read();
    if (!reader.exhausted())
      throw new IllegalArgumentException("Trailing bytes after IdentityState");
    Map<Object, Object> state = map(root);
    int version = integer(state.get(BigInteger.ONE)).intValueExact();
    IdentityId identity = IdentityId.of(bytes(state.get(BigInteger.TWO)));
    Sequence sequence = new Sequence(integer(state.get(BigInteger.valueOf(3))));
    IdentityStatus status =
        IdentityStatus.fromCode(integer(state.get(BigInteger.valueOf(4))).intValueExact());
    ControllerPolicy controller = controllerPolicy(state.get(BigInteger.valueOf(5)));
    RecoveryCommitment recovery =
        state.containsKey(BigInteger.valueOf(6))
            ? new RecoveryCommitment(MultihashSha256.of(bytes(state.get(BigInteger.valueOf(6)))))
            : null;

    return switch (version) {
      case 1 -> new IdentityStateV1(identity, sequence, status, controller, recovery);
      case 2 ->
          new IdentityStateV2(
              identity,
              sequence,
              status,
              controller,
              recovery,
              state.containsKey(BigInteger.valueOf(7))
                  ? assertionPolicy(state.get(BigInteger.valueOf(7)))
                  : null);
      default ->
          throw new IllegalArgumentException("Unsupported IdentityState version: " + version);
    };
  }

  /**
   * Decodes one complete canonical OpenIdentity operation into a module-neutral representation.
   *
   * @param bytes complete operation bytes
   * @return decoded operation fields
   * @throws IllegalArgumentException for malformed, unsupported, trailing, or non-canonical data
   */
  public static DecodedOperation decodeOperation(byte[] bytes) {
    CborReader reader = new CborReader(bytes);
    Object root = reader.read();
    if (!reader.exhausted()) {
      throw new IllegalArgumentException("Trailing bytes after Operation");
    }
    Map<Object, Object> operation = map(root);
    requireKeys(operation, 1, 2, 3, 4, 5, 6);
    int protocolVersion = integer(operation.get(BigInteger.ONE)).intValueExact();
    if (protocolVersion != 1) {
      throw new IllegalArgumentException("Unsupported protocolVersion: " + protocolVersion);
    }
    OperationType type =
        OperationType.fromCode(integer(operation.get(BigInteger.TWO)).intValueExact());
    IdentityId identity = IdentityId.of(bytes(operation.get(BigInteger.valueOf(3))));
    Sequence sequence = new Sequence(integer(operation.get(BigInteger.valueOf(4))));
    Object previousValue = operation.get(BigInteger.valueOf(5));
    StateHash previous =
        previousValue == null ? null : new StateHash(MultihashSha256.of(bytes(previousValue)));
    Map<Object, Object> payload = map(operation.get(BigInteger.valueOf(6)));

    DecodedOperation decoded =
        switch (type) {
          case CREATE -> decodeCreate(protocolVersion, identity, sequence, previous, payload);
          case ROTATE_CONTROLLER ->
              decodeRotate(protocolVersion, identity, sequence, previous, payload);
          case SET_ASSERTION_POLICY ->
              decodeAssertion(protocolVersion, identity, sequence, previous, payload);
          case DEACTIVATE ->
              decodeDeactivate(protocolVersion, identity, sequence, previous, payload);
          case RECOVER -> decodeRecover(protocolVersion, identity, sequence, previous, payload);
        };

    byte[] canonical = encodeDecodedOperation(decoded);
    if (!java.util.Arrays.equals(bytes, canonical)) {
      throw new IllegalArgumentException("Operation is not canonical deterministic CBOR");
    }
    return decoded;
  }

  private static DecodedOperation decodeCreate(
      int version,
      IdentityId identity,
      Sequence sequence,
      StateHash previous,
      Map<Object, Object> payload) {
    if (!sequence.equals(Sequence.of(1)) || previous != null) {
      throw new IllegalArgumentException("Invalid CREATE envelope");
    }
    if (!payload.containsKey(BigInteger.ONE)
        || payload.size() < 1
        || payload.size() > 2
        || (payload.size() == 2 && !payload.containsKey(BigInteger.TWO))) {
      throw new IllegalArgumentException("Invalid CREATE payload");
    }
    ControllerPolicy controller = controllerPolicy(payload.get(BigInteger.ONE));
    RecoveryCommitment recovery =
        payload.containsKey(BigInteger.TWO)
            ? new RecoveryCommitment(MultihashSha256.of(bytes(payload.get(BigInteger.TWO))))
            : null;
    return new DecodedOperation(
        version, OperationType.CREATE, identity, sequence, null, controller, null, null, recovery);
  }

  private static DecodedOperation decodeRotate(
      int version,
      IdentityId identity,
      Sequence sequence,
      StateHash previous,
      Map<Object, Object> payload) {
    requireNonCreateEnvelope(sequence, previous);
    requireKeys(payload, 1);
    return new DecodedOperation(
        version,
        OperationType.ROTATE_CONTROLLER,
        identity,
        sequence,
        previous,
        controllerPolicy(payload.get(BigInteger.ONE)),
        null,
        null,
        null);
  }

  private static DecodedOperation decodeAssertion(
      int version,
      IdentityId identity,
      Sequence sequence,
      StateHash previous,
      Map<Object, Object> payload) {
    requireNonCreateEnvelope(sequence, previous);
    requireKeys(payload, 1);
    Object value = payload.get(BigInteger.ONE);
    AssertionPolicy assertion = value == null ? null : assertionPolicy(value);
    return new DecodedOperation(
        version,
        OperationType.SET_ASSERTION_POLICY,
        identity,
        sequence,
        previous,
        null,
        assertion,
        null,
        null);
  }

  private static DecodedOperation decodeDeactivate(
      int version,
      IdentityId identity,
      Sequence sequence,
      StateHash previous,
      Map<Object, Object> payload) {
    requireNonCreateEnvelope(sequence, previous);
    if (!payload.isEmpty()) {
      throw new IllegalArgumentException("DEACTIVATE payload must be empty");
    }
    return new DecodedOperation(
        version, OperationType.DEACTIVATE, identity, sequence, previous, null, null, null, null);
  }

  private static DecodedOperation decodeRecover(
      int version,
      IdentityId identity,
      Sequence sequence,
      StateHash previous,
      Map<Object, Object> payload) {
    requireNonCreateEnvelope(sequence, previous);
    requireKeys(payload, 1, 2, 3);
    return new DecodedOperation(
        version,
        OperationType.RECOVER,
        identity,
        sequence,
        previous,
        controllerPolicy(payload.get(BigInteger.ONE)),
        null,
        recoveryPolicy(payload.get(BigInteger.TWO)),
        new RecoveryCommitment(MultihashSha256.of(bytes(payload.get(BigInteger.valueOf(3))))));
  }

  private static RecoveryPolicy recoveryPolicy(Object value) {
    Map<Object, Object> policy = map(value);
    requireKeys(policy, policy.size() == 3 ? new int[] {1, 2, 3} : new int[] {1, 2, 3, 4});
    int version = integer(policy.get(BigInteger.ONE)).intValueExact();
    if (version != RecoveryPolicy.VERSION) {
      throw new IllegalArgumentException("Unsupported RecoveryPolicy version: " + version);
    }
    int type = integer(policy.get(BigInteger.TWO)).intValueExact();
    if (type == 1) {
      List<VerificationMethod> methods = methods(policy.get(BigInteger.valueOf(3)));
      if (methods.size() != 1) throw new IllegalArgumentException("Invalid SINGLE RecoveryPolicy");
      return RecoveryPolicy.single(methods.getFirst());
    }
    if (type == 2) {
      return new RecoveryPolicy(
          integer(policy.get(BigInteger.valueOf(3))).intValueExact(),
          methods(policy.get(BigInteger.valueOf(4))));
    }
    throw new IllegalArgumentException("Unsupported RecoveryPolicy type: " + type);
  }

  private static byte[] encodeDecodedOperation(DecodedOperation operation) {
    return switch (operation.operationType()) {
      case CREATE ->
          OpenIdentityCborEncoder.encodeCreateOperation(
              operation.identity(), operation.controllerPolicy(), operation.recoveryCommitment());
      case ROTATE_CONTROLLER ->
          OpenIdentityCborEncoder.encodeRotateControllerOperation(
              operation.identity(),
              operation.sequence(),
              operation.previousStateHash(),
              operation.controllerPolicy());
      case SET_ASSERTION_POLICY ->
          OpenIdentityCborEncoder.encodeSetAssertionPolicyOperation(
              operation.identity(),
              operation.sequence(),
              operation.previousStateHash(),
              operation.assertionPolicy());
      case DEACTIVATE ->
          OpenIdentityCborEncoder.encodeDeactivateOperation(
              operation.identity(), operation.sequence(), operation.previousStateHash());
      case RECOVER ->
          OpenIdentityCborEncoder.encodeRecoverOperation(
              operation.identity(),
              operation.sequence(),
              operation.previousStateHash(),
              operation.controllerPolicy(),
              operation.recoveryPolicy(),
              operation.recoveryCommitment());
    };
  }

  private static void requireNonCreateEnvelope(Sequence sequence, StateHash previous) {
    if (sequence.value().compareTo(BigInteger.TWO) < 0 || previous == null) {
      throw new IllegalArgumentException(
          "Non-CREATE operation requires sequence >= 2 and predecessor");
    }
  }

  private static void requireKeys(Map<Object, Object> map, int... keys) {
    if (map.size() != keys.length) throw new IllegalArgumentException("Unexpected CBOR map fields");
    for (int key : keys) {
      if (!map.containsKey(BigInteger.valueOf(key))) {
        throw new IllegalArgumentException("Missing CBOR map field " + key);
      }
    }
  }

  private static ControllerPolicy controllerPolicy(Object value) {
    PolicyParts p = policy(value);
    return new ControllerPolicy(p.threshold(), p.methods());
  }

  private static AssertionPolicy assertionPolicy(Object value) {
    PolicyParts p = policy(value);
    return new AssertionPolicy(p.threshold(), p.methods());
  }

  private static PolicyParts policy(Object value) {
    Map<Object, Object> p = map(value);
    int type = integer(p.get(BigInteger.ONE)).intValueExact();
    if (type == 1) return new PolicyParts(1, methods(p.get(BigInteger.TWO)));
    if (type == 2)
      return new PolicyParts(
          integer(p.get(BigInteger.TWO)).intValueExact(), methods(p.get(BigInteger.valueOf(3))));
    throw new IllegalArgumentException("Unsupported policy type: " + type);
  }

  private static List<VerificationMethod> methods(Object value) {
    List<?> values = list(value);
    ArrayList<VerificationMethod> out = new ArrayList<>(values.size());
    for (Object item : values) out.add(method(item));
    return List.copyOf(out);
  }

  private static VerificationMethod method(Object value) {
    Map<Object, Object> m = map(value);
    VerificationMethodId id = VerificationMethodId.of(bytes(m.get(BigInteger.ONE)));
    Map<Object, Object> key = map(m.get(BigInteger.TWO));
    int kty = integer(key.get(BigInteger.ONE)).intValueExact();
    int alg = integer(key.get(BigInteger.valueOf(3))).intValueExact();
    CoseKey material;
    if (kty == 1 && alg == -8) {
      if (integer(key.get(BigInteger.valueOf(-1))).intValueExact() != 6)
        throw new IllegalArgumentException("Unsupported OKP curve");
      material = Ed25519Key.of(bytes(key.get(BigInteger.valueOf(-2))));
    } else if (kty == 7 && alg == -49) {
      material = MlDsa65Key.of(bytes(key.get(BigInteger.valueOf(-1))));
    } else throw new IllegalArgumentException("Unsupported OpenIdentity v0.1 COSE key");
    return new VerificationMethod(id, material);
  }

  @SuppressWarnings("unchecked")
  private static Map<Object, Object> map(Object value) {
    if (!(value instanceof Map<?, ?> m)) throw new IllegalArgumentException("Expected CBOR map");
    return (Map<Object, Object>) m;
  }

  private static List<?> list(Object value) {
    if (!(value instanceof List<?> l)) throw new IllegalArgumentException("Expected CBOR array");
    return l;
  }

  private static BigInteger integer(Object value) {
    if (!(value instanceof BigInteger i))
      throw new IllegalArgumentException("Expected CBOR integer");
    return i;
  }

  private static byte[] bytes(Object value) {
    if (!(value instanceof byte[] b))
      throw new IllegalArgumentException("Expected CBOR byte string");
    return b;
  }

  private record PolicyParts(int threshold, List<VerificationMethod> methods) {}
}
