import { bytesToHex } from "@noble/ciphers/utils.js";

import type { EncryptionKey } from "./asymmetric.js";
import { fromBase64 } from "./base64.js";

/**
 * Hashes the raw public key using SHA-256 and returns the first 16 hex characters.
 */
export const hashPublicKey = async (
  publicKey: EncryptionKey,
): Promise<string> => {
  const buffer = fromBase64(publicKey.toString()).buffer;
  const hash = await crypto.subtle.digest("SHA-256", buffer);

  return bytesToHex(new Uint8Array(hash, 0, 8));
};

export const validatePublicKeyHash = async (
  publicKey: EncryptionKey,
  hash: string,
): Promise<boolean> => {
  const computedHash = await hashPublicKey(publicKey);

  return computedHash === hash;
};

/**
 * determines/or generates the hash and dictates wether is host or not
 */
export const initHash = async (
  initialHash: string | undefined,
  encryptionKey: EncryptionKey,
) => {
  const ourHash = await hashPublicKey(encryptionKey);
  const hash = initialHash || ourHash;
  const isHost = hash === ourHash;

  return {
    hash,
    isHost,
  };
};
