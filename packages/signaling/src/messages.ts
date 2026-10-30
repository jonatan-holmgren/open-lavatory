import { MAX_PUBLIC_KEY_LENGTH, parsePeerCapabilities, type PeerCapabilities } from "@openlv/core";

export type SignalMessageBase<T extends string, P> = { type: T; payload: P; timestamp: number; };
export type SignalMessageFlash = SignalMessageBase<"flash", { nonce: string; wake?: true; wakeNonce?: string; }>;
export type SignalMessagePubkey = SignalMessageBase<"pubkey", { publicKey: string; clientNonce: string; hostNonce: string; }>;
export type SignalMessageCapabilities = SignalMessageBase<"capabilities", PeerCapabilities>;
export type SignalMessageData = SignalMessageBase<"data", object>;
export type SignalMessage = SignalMessageFlash | SignalMessagePubkey | SignalMessageCapabilities | SignalMessageData;

const isNonce = (value: unknown): value is string => typeof value === "string" && /^[0-9a-f]{32}$/.test(value);

/** Decrypted relay messages remain untrusted until their authentication is confirmed. */
export const parseSignalMessage = (raw: string): SignalMessage | undefined => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(raw);
  }
  catch { return undefined; }

  if (typeof parsed !== "object" || parsed === null) return undefined;

  const message = parsed as Record<string, unknown>;
  const { type, payload, timestamp } = message;

  if (typeof timestamp !== "number" || typeof payload !== "object" || payload === null || !Number.isFinite(timestamp) || Array.isArray(payload)) return undefined;

  const body = payload as Record<string, unknown>;

  switch (type) {
    case "flash": {
      if (!isNonce(body["nonce"]) || (body["wake"] !== undefined && body["wake"] !== true)
        || (body["wakeNonce"] !== undefined && !isNonce(body["wakeNonce"]))
        || (body["wake"] === true && body["wakeNonce"] !== undefined)) return undefined;

      return { type, payload: { nonce: body["nonce"], ...((body["wake"] === true) && { wake: true as const }), ...((typeof body["wakeNonce"] === "string") && { wakeNonce: body["wakeNonce"] }) }, timestamp };
    }
    case "pubkey": {
      if (typeof body["publicKey"] !== "string" || body["publicKey"].length === 0 || body["publicKey"].length > MAX_PUBLIC_KEY_LENGTH || !isNonce(body["clientNonce"]) || !isNonce(body["hostNonce"])) return undefined;

      return { type, payload: { publicKey: body["publicKey"], clientNonce: body["clientNonce"], hostNonce: body["hostNonce"] }, timestamp };
    }
    case "capabilities": {
      const capabilities = parsePeerCapabilities(payload);

      return capabilities ? { type, payload: capabilities, timestamp } : undefined;
    }
    case "data": { return { type, payload, timestamp };
    }
    default: { return undefined;
    }
  }
};
