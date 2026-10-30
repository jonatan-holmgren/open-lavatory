import { describe, expect, it } from "vitest";

import { parseSignalMessage } from "./messages.js";

const frame = (type: string, payload: unknown) =>
  JSON.stringify({ type, payload, timestamp: 1_750_000_000_000 });

describe("parseSignalMessage", () => {
  it("parses a capabilities packet with info", () => {
    const message = parseSignalMessage(
      frame("capabilities", {
        transports: ["wrtc", "ws"],
        info: {
          identity: "com.example.wallet",
          name: "Example Wallet",
          icon: "data:image/png;base64,aaaa",
        },
      }),
    );

    expect(message).toEqual({
      type: "capabilities",
      payload: {
        transports: ["wrtc", "ws"],
        info: {
          identity: "com.example.wallet",
          name: "Example Wallet",
          icon: "data:image/png;base64,aaaa",
        },
      },
      timestamp: 1_750_000_000_000,
    });
  });

  it("accepts an icon that is a URL -- content vetting is the renderer's job", () => {
    const message = parseSignalMessage(
      frame("capabilities", {
        transports: ["wrtc"],
        info: {
          identity: "com.example.wallet",
          name: "Example Wallet",
          icon: "https://example.com/icon.png",
        },
      }),
    );

    expect(message?.payload).toMatchObject({
      info: { icon: "https://example.com/icon.png" },
    });
  });

  it("parses a capabilities packet without info", () => {
    expect(
      parseSignalMessage(frame("capabilities", { transports: ["wrtc"] })),
    ).toMatchObject({ payload: { transports: ["wrtc"] } });
  });

  it("drops unknown extra fields from capabilities payloads", () => {
    const message = parseSignalMessage(
      frame("capabilities", { transports: ["wrtc"], extra: "field" }),
    );

    expect(message?.payload).toEqual({ transports: ["wrtc"] });
  });

  it("rejects capabilities without transports", () => {
    expect(parseSignalMessage(frame("capabilities", {}))).toBeUndefined();
    expect(parseSignalMessage(frame("capabilities", { transports: [] }))).toBeUndefined();
    expect(
      parseSignalMessage(frame("capabilities", { transports: [42] })),
    ).toBeUndefined();
  });

  it("rejects capabilities with malformed info", () => {
    const oversizedIcon = "x".repeat(10_000);

    expect(
      parseSignalMessage(
        frame("capabilities", { transports: ["wrtc"], info: { name: "No identity" } }),
      ),
    ).toBeUndefined();
    expect(
      parseSignalMessage(
        frame("capabilities", {
          transports: ["wrtc"],
          info: {
            identity: "com.example.wallet",
            name: "Example Wallet",
            icon: oversizedIcon,
          },
        }),
      ),
    ).toBeUndefined();
  });

  it("rejects retired and unknown packet types", () => {
    expect(parseSignalMessage(frame("ack", undefined))).toBeUndefined();
    expect(parseSignalMessage(frame("nonsense", {}))).toBeUndefined();
    expect(parseSignalMessage("not json")).toBeUndefined();
  });

  it("rejects the retired resume protocol and malformed nonces", () => {
    for (const type of ["resume", "resume-ack", "resume-confirm"]) {
      expect(parseSignalMessage(frame(type, { challenge: "old" }))).toBeUndefined();
    }
    expect(parseSignalMessage(frame("flash", { nonce: "short" }))).toBeUndefined();
    expect(parseSignalMessage(frame("flash", { nonce: "0".repeat(32), wakeNonce: "short" }))).toBeUndefined();
    expect(parseSignalMessage(frame("flash", { nonce: "0".repeat(32), wake: true, wakeNonce: "1".repeat(32) }))).toBeUndefined();
    expect(parseSignalMessage(frame("pubkey", { publicKey: "abc", clientNonce: "0".repeat(32), hostNonce: "1".repeat(31) }))).toBeUndefined();
  });

  it("rejects signaling messages without a numeric timestamp", () => {
    const messages = [
      ["flash", {}],
      ["pubkey", { publicKey: "abc" }],
      ["capabilities", { transports: ["wrtc"] }],
      ["data", {}],
      ["resume", {
        version: 1,
        pairingId: "pairing",
        publicKey: "public-key",
        challenge: "challenge",
        counter: 1,
      }],
      ["resume-ack", {
        version: 1,
        pairingId: "pairing",
        publicKey: "public-key",
        challenge: "challenge",
        initiatorChallenge: "initiator-challenge",
        counter: 1,
      }],
      ["resume-confirm", { pairingId: "pairing", challenge: "challenge" }],
    ] as const;

    for (const [type, payload] of messages) {
      expect(parseSignalMessage(JSON.stringify({ type, payload }))).toBeUndefined();
      expect(parseSignalMessage(JSON.stringify({ type, payload, timestamp: "now" })))
        .toBeUndefined();
    }
  });

  it("parses flash, pubkey, and data", () => {
    const clientNonce = "0".repeat(32);
    const hostNonce = "1".repeat(32);
    expect(parseSignalMessage(frame("flash", { nonce: clientNonce }))).toMatchObject({ type: "flash" });
    expect(parseSignalMessage(frame("flash", { nonce: clientNonce, wakeNonce: hostNonce })))
      .toMatchObject({ type: "flash", payload: { nonce: clientNonce, wakeNonce: hostNonce } });
    expect(parseSignalMessage(frame("pubkey", { publicKey: "abc", clientNonce, hostNonce }))).toMatchObject({ type: "pubkey" });
    expect(parseSignalMessage(frame("data", { anything: true }))).toMatchObject({ type: "data" });
  });
});
