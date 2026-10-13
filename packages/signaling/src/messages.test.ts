import { describe, expect, it } from "vitest";

import { MAX_ICON_LENGTH, parseSignalMessage, validatePeerInfo } from "./messages.js";

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
            // eslint-disable-next-line unicorn/max-nested-calls
            icon: "x".repeat(10_000),
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

  it("validates outgoing peer info with descriptive reasons", () => {
    expect(validatePeerInfo({ identity: "com.example.wallet", name: "Example Wallet" }))
      .toBeUndefined();
    expect(validatePeerInfo({
      identity: "com.example.wallet",
      name: "Example Wallet",
      icon: "data:image/png;base64,aaaa",
    })).toBeUndefined();
    expect(validatePeerInfo({ identity: "", name: "Example Wallet" }))
      .toMatch(/identity/);
    expect(validatePeerInfo({ identity: "com.example.wallet", name: "x".repeat(200) }))
      .toMatch(/name/);
    expect(validatePeerInfo({
      identity: "com.example.wallet",
      name: "Example Wallet",
      icon: "x".repeat(MAX_ICON_LENGTH + 1),
    })).toMatch(/icon/);
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

  it("parses resume and resume-ack packets", () => {
    const payload = {
      version: 1,
      pairingId: "pairingresume001",
      publicKey: "cHVibGlj",
      challenge: "challenge",
      counter: 42,
    };

    expect(parseSignalMessage(frame("resume", payload))).toEqual({
      type: "resume",
      payload,
      timestamp: 1_750_000_000_000,
    });

    expect(
      parseSignalMessage(frame("resume-ack", { ...payload, initiatorChallenge: "init" })),
    ).toEqual({
      type: "resume-ack",
      payload: { ...payload, initiatorChallenge: "init" },
      timestamp: 1_750_000_000_000,
    });
  });

  it("rejects malformed resume packets", () => {
    const base = {
      version: 1,
      pairingId: "pairingresume001",
      publicKey: "cHVibGlj",
      challenge: "challenge",
      counter: 1,
    };

    expect(parseSignalMessage(frame("resume", { ...base, pairingId: "" }))).toBeUndefined();
    expect(parseSignalMessage(frame("resume", { ...base, publicKey: 42 }))).toBeUndefined();
    expect(parseSignalMessage(frame("resume", { ...base, counter: -1 }))).toBeUndefined();
    expect(parseSignalMessage(frame("resume", { ...base, counter: 1.5 }))).toBeUndefined();
    expect(parseSignalMessage(frame("resume", { ...base, challenge: "" }))).toBeUndefined();
    expect(parseSignalMessage(frame("resume-ack", base))).toBeUndefined();
    expect(parseSignalMessage(frame("resume", { ...base, counter: Number.MAX_SAFE_INTEGER + 1 }))).toBeUndefined();
  });

  it("only accepts a resume-confirm proof shaped as a SHA-256 lowercase hex digest", () => {
    const payload = { pairingId: "pairingresume001", proof: "0123456789abcdef".repeat(4) };

    expect(parseSignalMessage(frame("resume-confirm", payload))).toMatchObject({
      type: "resume-confirm",
      payload,
    });

    for (const proof of ["", "a".repeat(63), "a".repeat(65), "A".repeat(64), "g".repeat(64), 42]) {
      expect(parseSignalMessage(frame("resume-confirm", { ...payload, proof }))).toBeUndefined();
    }
  });
});
