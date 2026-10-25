import { OPENLV_PROTOCOL_VERSION } from "@openlv/core";
import {
  deriveSymmetricKey,
  generateKeyPair,
  hashPublicKey,
} from "@openlv/core/encryption";
import { describe, expect, it, vi } from "vitest";

import { createSignalingLayer } from "./index.js";
import type { SignalingChannel } from "./protocol.js";

describe("signaling resume error classification", () => {
  it("does not invalidate a saved pairing when publishing a valid resume acknowledgement fails", async () => {
    const local = await generateKeyPair();
    const peer = await generateKeyPair();
    const publish = vi.fn(async () => {
      throw new Error("relay unavailable");
    });
    let receive: ((payload: string) => Promise<void>) | undefined;
    const channel: SignalingChannel = {
      type: "memory",
      setup: () => {},
      teardown: () => {},
      publish,
      subscribe: (handler) => {
        receive = handler as (payload: string) => Promise<void>;
      },
    };
    const layer = await createSignalingLayer(channel)({
      isHost: true,
      h: await hashPublicKey(local.encryptionKey),
      k: await deriveSymmetricKey("00112233445566778899aabbccddeeff"),
      capabilities: { transports: ["wrtc"] },
      publicKey: local.encryptionKey,
      expectedPeerKey: peer.encryptionKey,
      resume: {
        pairingId: "pairing",
        lastCounter: 4,
        lastSeenCounter: 2,
        lastSeenAckCounter: 2,
        initiate: false,
        persist: () => {},
      },
      canEncrypt: () => true,
      encrypt: message => peer.encryptionKey.encrypt(message),
      decrypt: message => local.decryptionKey.decrypt(message),
    });
    const invalidation: (boolean | undefined)[] = [];

    layer.on("error", (_reason, isPairingInvalidated) => {
      invalidation.push(isPairingInvalidated);
    });
    await layer.setup();

    const resume = JSON.stringify({
      type: "resume",
      payload: {
        version: OPENLV_PROTOCOL_VERSION,
        pairingId: "pairing",
        publicKey: peer.encryptionKey.toString(),
        challenge: "fresh-challenge",
        counter: 3,
      },
      timestamp: Date.now(),
    });
    const encrypted = await local.encryptionKey.encrypt(resume);

    await receive?.(`xh${encrypted}`);

    expect(publish).toHaveBeenCalledOnce();
    expect(invalidation).toEqual([false]);
    await layer.teardown();
  });
});
