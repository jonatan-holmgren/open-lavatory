import type { SessionConnectionParameters } from "@openlv/core";
import type { TransportLayerFunction } from "@openlv/transport";
import { describe, expect, it } from "vitest";

import { createSession } from "./index.js";

const savedParameters = {
  version: 1 as const,
  sessionId: "session-id",
  h: "hash",
  k: "key",
  p: "ntfy",
  s: "https://ntfy.sh/",
  relyingPublicKey: "peer-key",
  encryptionKey: "own-public-key",
  decryptionKey: "own-private-key",
  pairingId: "pairing-id",
  transportId: "wrtc",
  lastCounter: 1,
  lastSeenCounter: 1,
  lastSeenAckCounter: 1,
} satisfies SessionConnectionParameters;

const transport: TransportLayerFunction = {
  transportId: "wrtc",
  create: () => {
    throw new Error("Transport creation is not reached");
  },
};

describe("saved session persistence contract", () => {
  it("rejects resumption without a synchronous persistence callback", async () => {
    await expect(createSession(savedParameters, [transport], async () => ({})))
      .rejects.toThrow("Resuming a saved session requires durable connection parameter persistence");
  });
});
