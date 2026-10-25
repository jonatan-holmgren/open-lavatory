import { parsePeerCapabilities, type PeerCapabilities } from "@openlv/core";

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

export type SignalMessage
  = | SignalMessageFlash
    | SignalMessagePubkey
    | SignalMessageCapabilities
    | SignalMessageData;

/**
 * Parse and shape-check a decrypted signaling payload. The relay topic is
 * public, so decrypted JSON is still untrusted input: anything that does not
 * match one of the four message shapes is dropped (returns undefined).
 */
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

  switch (message["type"]) {
    case "flash": {
      return typeof message["payload"] === "object" && message["payload"] !== null
        ? (message as SignalMessageFlash)
        : undefined;
    }
    case "pubkey": {
      const payload = message["payload"] as Record<string, unknown> | null;

      return typeof payload === "object"
        && payload !== null
        && typeof payload["publicKey"] === "string"
        ? (message as SignalMessagePubkey)
        : undefined;
    }
    case "capabilities": {
      const capabilities = parsePeerCapabilities(message["payload"]);

      if (!capabilities) return undefined;

      return {
        type: "capabilities",
        payload: capabilities,
        timestamp: message["timestamp"] as number,
      };
    }
    case "data": {
      return typeof message["payload"] === "object" && message["payload"] !== null
        ? (message as SignalMessageData)
        : undefined;
    }
    default: {
      return undefined;
    }
  }
};
