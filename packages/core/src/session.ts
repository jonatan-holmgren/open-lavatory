import { x25519 } from "@noble/curves/ed25519.js";
import { z } from "zod";

import { fromBase64 } from "./encryption/base64.js";
import {
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

/** Base64 X25519 key material. Branded so raw strings cannot be mixed in. */
export type SerializedEncryptionKey = string & {
  readonly __serializedEncryptionKey: unique symbol;
};

export const MAX_PAIRING_ID_LENGTH = 64;
export const MAX_RESUME_CHALLENGE_LENGTH = 128;
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
  // Hash of peerA's public key
  h: Hex<16>;
  // Shared key for symmetric encryption during handshake (32 hex chars = 16 bytes)
  k: Hex<32>;
  // Protocol for signaling
  p: string;
  // Signaling server URL
  s: string;
};

/** Durable replay state shared by the session and signaling layers. */
export type SessionResumeState = {
  // Durable pairing identity.
  pairingId: string;
  // Locally sent resume/ack high-water mark.
  lastCounter: number;
  // Highest resume counter received and confirmed from the peer.
  lastSeenCounter: number;
  // Highest resume-ack counter received from the peer.
  lastSeenAckCounter: number;
};

/**
 * The parameters that describe a session
 * these can be used to restart a session
 */
export type SessionConnectionParameters = SessionHandshakeParameters
  & SessionResumeState & {
    // The peer public key used to encrypt messages during signaling.
    relyingPublicKey: SerializedEncryptionKey;
    // Our serialized public key.
    encryptionKey: SerializedEncryptionKey;
    // Our serialized private key.
    decryptionKey: SerializedEncryptionKey;
    // Transport negotiated before persistence.
    transportId: string;
    // Peer capabilities observed before persistence.
    peerCapabilities?: PeerCapabilities;
  };

export const SESSION_CONNECTION_PARAMETER_KEYS = [
  "relyingPublicKey",
  "encryptionKey",
  "decryptionKey",
  "pairingId",
  "transportId",
  "lastCounter",
  "lastSeenCounter",
  "lastSeenAckCounter",
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
  pairingId: z.string().min(1)
    .max(MAX_PAIRING_ID_LENGTH),
  transportId: z.string().min(1)
    .max(MAX_TRANSPORT_ID_LENGTH),
  lastCounter: z.number().int()
    .nonnegative()
    .safe(),
  lastSeenCounter: z.number().int()
    .nonnegative()
    .safe(),
  lastSeenAckCounter: z.number().int()
    .nonnegative()
    .safe(),
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

    return parameters.h === ourHash || parameters.h === peerHash;
  }
  catch {
    return false;
  }
};
