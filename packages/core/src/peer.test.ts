import { describe, expect, it } from "vitest";

import { validatePeerInfo } from "./peer.js";

describe("outgoing peer info", () => {
  it("accepts metadata with and without an icon", () => {
    expect(validatePeerInfo({ identity: "com.example.wallet", name: "Example Wallet" }))
      .toBeUndefined();
    expect(validatePeerInfo({
      identity: "com.example.wallet",
      name: "Example Wallet",
      icon: "data:image/png;base64,aaaa",
    })).toBeUndefined();
  });

  it("rejects metadata outside the wire limits", () => {
    expect(validatePeerInfo({ identity: "", name: "Example Wallet" }))
      .toBeTypeOf("string");
    expect(validatePeerInfo({ identity: "com.example.wallet", name: "x".repeat(200) }))
      .toBeTypeOf("string");
    expect(validatePeerInfo({
      identity: "com.example.wallet",
      name: "Example Wallet",
      icon: "x".repeat(8193),
    })).toBeTypeOf("string");
  });
});
