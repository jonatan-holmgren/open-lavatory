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

  it("parses a resume-confirm challenge echo", () => {
    expect(parseSignalMessage(frame("resume-confirm", {
      pairingId: "pairing",
      challenge: "fresh-responder-challenge",
    }))).toMatchObject({
      type: "resume-confirm",
      payload: { pairingId: "pairing", challenge: "fresh-responder-challenge" },
    });
    const invalidConfirm = frame("resume-confirm", {
      pairingId: "pairing",
      proof: "a".repeat(64),
    });

    expect(parseSignalMessage(invalidConfirm)).toBeUndefined();
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

  it("still parses flash, pubkey, and data", () => {
    expect(parseSignalMessage(frame("flash", {}))).toMatchObject({ type: "flash" });
    expect(
      parseSignalMessage(frame("pubkey", { publicKey: "abc" })),
    ).toMatchObject({ type: "pubkey" });
    expect(
      parseSignalMessage(frame("data", { anything: true })),
    ).toMatchObject({ type: "data" });
  });
});
