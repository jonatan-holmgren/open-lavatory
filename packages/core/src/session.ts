import { OPENLV_PROTOCOL_VERSION } from "./url/index.js";
import { isObject, isReplayCounter } from "./validation.js";

// typescript type for 32 character hex string
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export type Hex<_L> = string;

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

/**
 * The parameters that describe a session
 * these can be used to restart a session
 */
export type SessionConnectionParameters = SessionHandshakeParameters & {
  // The peer public key used to encrypt messages during signaling.
  relyingPublicKey: string;
  // Our serialized public key.
  encryptionKey: string;
  // Our serialized private key.
  decryptionKey: string;
  // Durable pairing identity.
  pairingId: string;
  // Transport negotiated before persistence.
  transportId: string;
  // Locally sent resume/ack high-water mark.
  lastCounter: number;
  // Highest resume counter received from the peer.
  lastSeenCounter: number;
  // Highest resume-ack counter received from the peer.
  lastSeenAckCounter: number;
};

export type SessionCreationParameters = Pick<
  SessionHandshakeParameters,
  "p" | "s"
>;

export type SessionLinkParameters
  = | SessionConnectionParameters
    | SessionHandshakeParameters
    | SessionCreationParameters;

export const parseSessionConnectionParameters = (
  value: unknown,
): SessionConnectionParameters | undefined => {
  if (!isObject(value)) return undefined;

  const record = value;

  const stringFields = [
    "sessionId",
    "h",
    "k",
    "p",
    "s",
    "relyingPublicKey",
    "encryptionKey",
    "decryptionKey",
    "pairingId",
    "transportId",
  ] as const;
  const counterFields = [
    "lastCounter",
    "lastSeenCounter",
    "lastSeenAckCounter",
  ] as const;

  if (
    record["version"] !== OPENLV_PROTOCOL_VERSION
    || stringFields.some(field => typeof record[field] !== "string" || record[field].length === 0)
    || (record["pairingId"] as string).length > 64
    || (record["transportId"] as string).length > 32
    || counterFields.some(field => !isReplayCounter(record[field]))
  ) {
    return undefined;
  }

  return record as unknown as SessionConnectionParameters;
};
