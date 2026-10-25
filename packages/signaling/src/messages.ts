import {
  MAX_PAIRING_ID_LENGTH,
  MAX_PUBLIC_KEY_LENGTH,
  MAX_RESUME_CHALLENGE_LENGTH,
  OPENLV_PROTOCOL_VERSION,
  parsePeerCapabilities,
  type PeerCapabilities,
} from "@openlv/core";

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
 * Starts a resume attempt. The payload is authenticated only after the peer
 * key and challenge exchanges complete.
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
 * Confirms receipt of the responder's fresh challenge, demonstrating access
 * to the pinned initiator key that decrypted the resume acknowledgement.
 */
export type SignalMessageResumeConfirm = SignalMessageBase<
  "resume-confirm",
  {
    pairingId: string;
    challenge: string;
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

const isBoundedString = (value: unknown, maxLength: number): value is string =>
  typeof value === "string" && value.length > 0 && value.length <= maxLength;

/**
 * Parse and shape-check a decrypted signaling payload. The relay topic is
 * public, so decrypted JSON is still untrusted input: anything that does not
 * match one of the supported message shapes is dropped (returns undefined).
 */
const parseResumePayload = (raw: unknown): SignalMessageResume["payload"] | undefined => {
  if (typeof raw !== "object" || raw === null) return undefined;

  const payload = raw as Record<string, unknown>;

  if (payload["version"] !== OPENLV_PROTOCOL_VERSION) return undefined;

  if (!isBoundedString(payload["pairingId"], MAX_PAIRING_ID_LENGTH)) return undefined;

  if (!isBoundedString(payload["publicKey"], MAX_PUBLIC_KEY_LENGTH)) return undefined;

  if (!isBoundedString(payload["challenge"], MAX_RESUME_CHALLENGE_LENGTH)) return undefined;

  const counter = payload["counter"];

  if (
    typeof counter !== "number"
    || !Number.isSafeInteger(counter)
    || counter < 0
  ) {
    return undefined;
  }

  return {
    version: payload["version"],
    pairingId: payload["pairingId"],
    publicKey: payload["publicKey"],
    challenge: payload["challenge"],
    counter,
  };
};

const parseResumeAckPayload = (raw: unknown): SignalMessageResumeAck["payload"] | undefined => {
  if (typeof raw !== "object" || raw === null) return undefined;

  const payload = raw as Record<string, unknown>;

  if (!isBoundedString(payload["initiatorChallenge"], MAX_RESUME_CHALLENGE_LENGTH)) return undefined;

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
  if (typeof raw !== "object" || raw === null) return undefined;

  const payload = raw as Record<string, unknown>;

  if (!isBoundedString(payload["pairingId"], MAX_PAIRING_ID_LENGTH)) return undefined;

  if (!isBoundedString(payload["challenge"], MAX_RESUME_CHALLENGE_LENGTH)) return undefined;

  return {
    pairingId: payload["pairingId"],
    challenge: payload["challenge"],
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

  if (typeof parsed !== "object" || parsed === null) return undefined;

  const message = parsed as Record<string, unknown>;
  const timestamp = message["timestamp"];

  if (typeof timestamp !== "number" || !Number.isFinite(timestamp)) {
    return undefined;
  }

  switch (message["type"]) {
    case "flash": {
      return typeof message["payload"] === "object" && message["payload"] !== null
        ? (message as SignalMessageFlash)
        : undefined;
    }
    case "pubkey": {
      const payload = message["payload"];

      if (typeof payload !== "object" || payload === null) return undefined;

      const body = payload as Record<string, unknown>;

      return typeof body["publicKey"] === "string"
        ? (message as SignalMessagePubkey)
        : undefined;
    }
    case "capabilities": {
      const capabilities = parsePeerCapabilities(message["payload"]);

      if (!capabilities) return undefined;

      return {
        type: "capabilities",
        payload: capabilities,
        timestamp,
      };
    }
    case "data": {
      return typeof message["payload"] === "object" && message["payload"] !== null
        ? (message as SignalMessageData)
        : undefined;
    }
    case "resume": {
      const payload = parseResumePayload(message["payload"]);

      if (!payload) return undefined;

      return {
        type: "resume",
        payload,
        timestamp,
      };
    }
    case "resume-ack": {
      const payload = parseResumeAckPayload(message["payload"]);

      if (!payload) return undefined;

      return {
        type: "resume-ack",
        payload,
        timestamp,
      };
    }
    case "resume-confirm": {
      const payload = parseResumeConfirmPayload(message["payload"]);

      if (!payload) return undefined;

      return {
        type: "resume-confirm",
        payload,
        timestamp,
      };
    }
    default: {
      return undefined;
    }
  }
};
