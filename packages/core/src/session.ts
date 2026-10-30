import { x25519 } from "@noble/curves/ed25519.js";
import { z } from "zod";

import { fromBase64 } from "./encryption/base64.js";
import {
  deriveResumptionSecret,
  hashPublicKey,
  isSerializedKey,
  parseEncryptionKey,
  serializedPublicKey,
} from "./encryption/index.js";
import {
  MAX_TRANSPORT_ID_LENGTH,
  parsePeerCapabilities,
  type PeerCapabilities,
} from "./peer.js";
import {
  HANDSHAKE_KEY_PATTERN,
  OPENLV_PROTOCOL_VERSION,
  PUBLIC_KEY_HASH_PATTERN,
  SESSION_ID_PATTERN,
} from "./url/index.js";

// typescript type for 32 character hex string
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export type Hex<_L> = string;

export type SerializedEncryptionKey = string & {
  readonly __serializedEncryptionKey: unique symbol;
};

export const MAX_PUBLIC_KEY_LENGTH = 128;
export const SESSION_SETUP_TIMEOUT_MS = 45_000;

/**
 * The parameters from the connection url
 */
export type SessionHandshakeParameters = {
  // Version of the openlv protocol
  version: 1;
  // Unique session identifier
  sessionId: Hex<16>;
  // First 16 hex characters of SHA-256 of the host's public key
  h: Hex<16>;
  // Shared key for symmetric encryption during handshake (32 hex chars = 16 bytes)
  k: Hex<32>;
  // Protocol for signaling
  p: string;
  // Signaling server URL
  s: string;
};

/**
 * The parameters that describe a session
 * these can be used to restart a session
 */
export type SessionConnectionParameters = SessionHandshakeParameters & {
  // The peer public key used to encrypt messages during signaling.
  relyingPublicKey: SerializedEncryptionKey;
  // Our serialized public key.
  encryptionKey: SerializedEncryptionKey;
  // Our serialized private key.
  decryptionKey: SerializedEncryptionKey;
  // Stable secret derived from the invitation PSK and pinned key pair.
  resumptionSecret: string;
  // Transport negotiated before persistence.
  transportId: string;
  // Peer capabilities observed before persistence.
  peerCapabilities?: PeerCapabilities;
};

export const SESSION_CONNECTION_PARAMETER_KEYS = [
  "relyingPublicKey",
  "encryptionKey",
  "decryptionKey",
  "resumptionSecret",
  "transportId",
] as const;

export type SessionCreationParameters = Pick<
  SessionHandshakeParameters,
  "p" | "s"
>;

export type SessionLinkParameters
  = | SessionConnectionParameters
    | SessionHandshakeParameters
    | SessionCreationParameters;

const serializedEncryptionKeySchema = z.string()
  .refine(isSerializedKey)
  .transform(value => value as SerializedEncryptionKey);

const peerCapabilitiesSchema = z.custom<PeerCapabilities>(
  value => parsePeerCapabilities(value) !== undefined,
).transform(value => parsePeerCapabilities(value)!);

const sessionConnectionParametersSchema = z.object({
  version: z.literal(OPENLV_PROTOCOL_VERSION),
  sessionId: z.string().regex(SESSION_ID_PATTERN),
  h: z.string().regex(PUBLIC_KEY_HASH_PATTERN),
  k: z.string().regex(HANDSHAKE_KEY_PATTERN),
  p: z.string().min(1),
  s: z.string().min(1),
  relyingPublicKey: serializedEncryptionKeySchema,
  encryptionKey: serializedEncryptionKeySchema,
  decryptionKey: serializedEncryptionKeySchema,
  resumptionSecret: z.string().regex(/^[0-9a-f]{64}$/),
  transportId: z.string().min(1)
    .max(MAX_TRANSPORT_ID_LENGTH),
  peerCapabilities: peerCapabilitiesSchema.optional(),
});

export const parseSessionConnectionParameters = (
  value: unknown,
): SessionConnectionParameters | undefined => {
  const parsed = sessionConnectionParametersSchema.safeParse(value);

  return parsed.success ? parsed.data : undefined;
};

/**
 * Verify that saved key material is internally consistent and the pinned peer
 * key supports X25519 key agreement. The protocol hash commits to either our key
 * (advertising peer) or the pinned peer key (joining peer).
 */
export const validateSessionConnectionKeys = async (
  parameters: SessionConnectionParameters,
): Promise<boolean> => {
  try {
    if (serializedPublicKey(parameters.decryptionKey) !== parameters.encryptionKey) {
      return false;
    }

    // X25519 rejects low-order peer keys that would yield an all-zero secret.
    x25519.getSharedSecret(
      fromBase64(parameters.decryptionKey),
      fromBase64(parameters.relyingPublicKey),
    );

    const [ourKey, peerKey] = await Promise.all([
      parseEncryptionKey(parameters.encryptionKey),
      parseEncryptionKey(parameters.relyingPublicKey),
    ]);
    const [ourHash, peerHash] = await Promise.all([
      hashPublicKey(ourKey),
      hashPublicKey(peerKey),
    ]);

    const isHost = parameters.h === ourHash;

    if (!isHost && parameters.h !== peerHash) return false;

    return parameters.resumptionSecret === await deriveResumptionSecret({
      version: parameters.version,
      sessionId: parameters.sessionId,
      role: isHost ? "host" : "client",
      localSecretKey: parameters.decryptionKey,
      hostPublicKey: isHost ? parameters.encryptionKey : parameters.relyingPublicKey,
      clientPublicKey: isHost ? parameters.relyingPublicKey : parameters.encryptionKey,
      psk: parameters.k,
    });
  }
  catch {
    return false;
  }
};
