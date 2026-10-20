import type { SerializedEncryptionKey, SessionConnectionParameters } from "@openlv/core";
import { generateKeyPair, hashPublicKey } from "@openlv/core/encryption";
import type { TransportLayerFunction } from "@openlv/transport";
import { describe, expect, it } from "vitest";

import { createSession } from "./index.js";

const createSavedParameters = async (): Promise<SessionConnectionParameters> => {
  const local = await generateKeyPair();
  const peer = await generateKeyPair();

  return {
    version: 1 as const,
    sessionId: "mytestsession111",
    h: await hashPublicKey(local.encryptionKey),
    k: "0".repeat(32),
    p: "ntfy",
    s: "https://ntfy.sh/",
    relyingPublicKey: peer.encryptionKey.toString() as SerializedEncryptionKey,
    encryptionKey: local.encryptionKey.toString() as SerializedEncryptionKey,
    decryptionKey: local.decryptionKey.toString() as SerializedEncryptionKey,
    pairingId: "pairing-id",
    transportId: "wrtc",
    lastCounter: 1,
    lastSeenCounter: 1,
    lastSeenAckCounter: 1,
  };
};

const transport: TransportLayerFunction = {
  transportId: "wrtc",
  create: () => {
    throw new Error("Transport creation is not reached");
  },
};

describe("saved session persistence contract", () => {
  it("rejects resumption without a synchronous persistence callback", async () => {
    await expect(createSession(await createSavedParameters(), [transport], async () => ({})))
      .rejects.toThrow("Resuming a saved session requires durable connection parameter persistence");
  });
});
