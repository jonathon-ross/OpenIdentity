package org.openidentity.core;

/**
 * Supported authoritative public key represented using OpenIdentity's COSE_Key profile.
 *
 * <p>Algorithm selection during verification comes from this key, never from a proof-supplied
 * algorithm identifier.
 */
public sealed interface CoseKey permits Ed25519Key, MlDsa65Key {
  /**
   * @return COSE key-type registry value
   */
  int coseKeyType();

  /**
   * @return COSE algorithm registry value
   */
  int coseAlgorithm();

  /**
   * @return defensive copy of raw algorithm-specific public-key bytes
   */
  byte[] publicKey();
}
