import { isObject, isReplayCounter, OPENLV_PROTOCOL_VERSION } from "@openlv/core";

export type SignalMessageBase<T extends string, P> = {
  type: T;
  payload: P;
  timestamp: number;
};

/**
 * Flash message
 * Sent to initiate handshake by non-host
 */
export type SignalMessageFlash = SignalMessageBase<"flash", object>;

export type SignalMessagePubkey = SignalMessageBase<
  "pubkey",
  {
    publicKey: string;
  }
>;

/** Optional self-description shown in the other peer's UI. */
export type PeerInfo = {
  /** Reverse-DNS application identifier, e.g. "com.example.wallet". */
  identity: string;
  name: string;
  /**
   * A data URI or an image URL. Only size is enforced on the wire -- anyone
   * rendering or fetching it is responsible for sanity-checking it first.
   */
  icon?: string;
};

export type PeerCapabilities = {
  /** Supported transport identifiers, in preference order. */
  transports: string[];
  info?: PeerInfo;
};

/**
 * Completes the handshake: acknowledges the previous step, negotiates the
 * transport, and shares peer metadata in a single packet.
 */
export type SignalMessageCapabilities = SignalMessageBase<
  "capabilities",
  PeerCapabilities
>;

export type SignalMessageData = SignalMessageBase<"data", object>;

/**
 * Initiates an authenticated resume of an existing pairing. Encrypted to the
 * peer's pinned static key, so it is accepted even while already encrypted.
 */
export type SignalMessageResume = SignalMessageBase<
  "resume",
  {
    version: number;
    pairingId: string;
    publicKey: string;
    challenge: string;
    counter: number;
  }
>;

/**
 * Answers a resume. Echoes the initiator's challenge so a stale or replayed
 * ack cannot complete the handshake.
 */
export type SignalMessageResumeAck = SignalMessageBase<
  "resume-ack",
  {
    version: number;
    pairingId: string;
    publicKey: string;
    challenge: string;
    initiatorChallenge: string;
    counter: number;
  }
>;

/**
 * Proves the initiator decrypted the responder's fresh challenge, which is only
 * possible for the holder of the pinned private key.
 */
export type SignalMessageResumeConfirm = SignalMessageBase<
  "resume-confirm",
  {
    pairingId: string;
    proof: string;
  }
>;

export type SignalMessage
  = | SignalMessageFlash
    | SignalMessagePubkey
    | SignalMessageCapabilities
    | SignalMessageData
    | SignalMessageResume
    | SignalMessageResumeAck
    | SignalMessageResumeConfirm;

const MAX_TRANSPORTS = 8;
const MAX_TRANSPORT_ID_LENGTH = 32;
const MAX_TEXT_LENGTH = 128;
const MAX_PAIRING_ID_LENGTH = 64;
const MAX_CHALLENGE_LENGTH = 128;
const MAX_PUBLIC_KEY_LENGTH = 128;

// Relay message limits (ntfy in particular) leave little room after base64
// and encryption overhead; oversized icons would silently fail to deliver,
// so they are rejected here instead.
export const MAX_ICON_LENGTH = 8192;

const isBoundedString = (value: unknown, maxLength: number): value is string =>
  typeof value === "string" && value.length > 0 && value.length <= maxLength;

/**
 * Check outgoing peer info against the wire limits enforced by receivers.
 * Returns a human-readable problem, or undefined when the info is sendable.
 * Senders must use this: a receiver silently drops an oversized packet, which
 * would otherwise surface only as a generic handshake timeout.
 */
export const validatePeerInfo = (info: PeerInfo): string | undefined => {
  if (!isBoundedString(info.identity, MAX_TEXT_LENGTH)) {
    return `info.identity must be 1-${MAX_TEXT_LENGTH} characters`;
  }

  if (!isBoundedString(info.name, MAX_TEXT_LENGTH)) {
    return `info.name must be 1-${MAX_TEXT_LENGTH} characters`;
  }

  if (info.icon !== undefined && !isBoundedString(info.icon, MAX_ICON_LENGTH)) {
    return `info.icon must be 1-${MAX_ICON_LENGTH} characters -- use a smaller image or an image URL`;
  }

  return undefined;
};

const parsePeerInfo = (raw: unknown): PeerInfo | undefined => {
  if (!isObject(raw)) return undefined;

  const info = raw;

  if (!isBoundedString(info["identity"], MAX_TEXT_LENGTH)) return undefined;

  if (!isBoundedString(info["name"], MAX_TEXT_LENGTH)) return undefined;

  if (info["icon"] !== undefined && !isBoundedString(info["icon"], MAX_ICON_LENGTH)) {
    return undefined;
  }

  return {
    identity: info["identity"],
    name: info["name"],
    ...(info["icon"] !== undefined && { icon: info["icon"] }),
  };
};

export const parseCapabilities = (raw: unknown): PeerCapabilities | undefined => {
  if (!isObject(raw)) return undefined;

  const payload = raw;
  const transports = payload["transports"];

  if (
    !Array.isArray(transports)
    || transports.length === 0
    || transports.length > MAX_TRANSPORTS
    || transports.some(transportId => !isBoundedString(transportId, MAX_TRANSPORT_ID_LENGTH))
  ) {
    return undefined;
  }

  if (payload["info"] === undefined) return { transports };

  const info = parsePeerInfo(payload["info"]);

  if (!info) return undefined;

  return { transports, info };
};
export type ResumePayload = Extract<
  SignalMessageResume["payload"],
  object
>;

/**
 * Parse and shape-check a decrypted signaling payload. The relay topic is
 * public, so decrypted JSON is still untrusted input: anything that does not
 * match one of the four message shapes is dropped (returns undefined).
 */
const parseResumePayload = (raw: unknown): ResumePayload | undefined => {
  if (!isObject(raw)) return undefined;

  const payload = raw;

  if (payload["version"] !== OPENLV_PROTOCOL_VERSION) return undefined;

  if (!isBoundedString(payload["pairingId"], MAX_PAIRING_ID_LENGTH)) return undefined;

  if (!isBoundedString(payload["publicKey"], MAX_PUBLIC_KEY_LENGTH)) return undefined;

  if (!isBoundedString(payload["challenge"], MAX_CHALLENGE_LENGTH)) return undefined;

  if (!isReplayCounter(payload["counter"])) return undefined;

  return {
    version: payload["version"],
    pairingId: payload["pairingId"],
    publicKey: payload["publicKey"],
    challenge: payload["challenge"],
    counter: payload["counter"],
  };
};

const parseResumeAckPayload = (raw: unknown): SignalMessageResumeAck["payload"] | undefined => {
  if (!isObject(raw)) return undefined;

  const payload = raw;

  if (!isBoundedString(payload["initiatorChallenge"], MAX_CHALLENGE_LENGTH)) return undefined;

  const base = parseResumePayload(raw);

  if (!base) return undefined;

  return {
    ...base,
    initiatorChallenge: payload["initiatorChallenge"],
  };
};

const parseResumeConfirmPayload = (
  raw: unknown,
): SignalMessageResumeConfirm["payload"] | undefined => {
  if (!isObject(raw)) return undefined;

  const payload = raw;

  if (!isBoundedString(payload["pairingId"], MAX_PAIRING_ID_LENGTH)) return undefined;

  if (typeof payload["proof"] !== "string" || !/^[a-f0-9]{64}$/.test(payload["proof"])) return undefined;

  return {
    pairingId: payload["pairingId"],
    proof: payload["proof"],
  };
};

export const parseSignalMessage = (raw: string): SignalMessage | undefined => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(raw);
  }
  catch {
    return undefined;
  }

  if (!isObject(parsed)) return undefined;

  const message = parsed;

  switch (message["type"]) {
    case "flash": {
      return isObject(message["payload"])
        ? (message as SignalMessageFlash)
        : undefined;
    }
    case "pubkey": {
      const payload = message["payload"];

      return isObject(payload)
        && typeof payload["publicKey"] === "string"
        ? (message as SignalMessagePubkey)
        : undefined;
    }
    case "capabilities": {
      const capabilities = parseCapabilities(message["payload"]);

      if (!capabilities) return undefined;

      return {
        type: "capabilities",
        payload: capabilities,
        timestamp: message["timestamp"] as number,
      };
    }
    case "data": {
      return isObject(message["payload"])
        ? (message as SignalMessageData)
        : undefined;
    }
    case "resume": {
      const payload = parseResumePayload(message["payload"]);

      if (!payload) return undefined;

      return {
        type: "resume",
        payload,
        timestamp: message["timestamp"] as number,
      };
    }
    case "resume-ack": {
      const payload = parseResumeAckPayload(message["payload"]);

      if (!payload) return undefined;

      return {
        type: "resume-ack",
        payload,
        timestamp: message["timestamp"] as number,
      };
    }
    case "resume-confirm": {
      const payload = parseResumeConfirmPayload(message["payload"]);

      if (!payload) return undefined;

      return {
        type: "resume-confirm",
        payload,
        timestamp: message["timestamp"] as number,
      };
    }
    default: {
      return undefined;
    }
  }
};
