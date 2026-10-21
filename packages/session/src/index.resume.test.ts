import { observable, type SerializedEncryptionKey, type SessionConnectionParameters } from "@openlv/core";
import { generateKeyPair, hashPublicKey } from "@openlv/core/encryption";
import {
  type PeerCapabilities,
  type SignalingLayer,
  Status as SignalingStatus,
} from "@openlv/signaling";
import type { TransportLayerFunction } from "@openlv/transport";
import { EventEmitter } from "eventemitter3";
import { expect, it, vi } from "vitest";

const { loadSignaling } = vi.hoisted(() => ({ loadSignaling: vi.fn() }));

vi.mock("./dynamic.js", () => ({
  loadSignaling,
  loadTransport: vi.fn(),
}));

import { createSession, InvalidSavedSessionError } from "./index.js";

const createSavedState = async () => {
  const local = await generateKeyPair();
  const peer = await generateKeyPair();
  const parameters: SessionConnectionParameters = {
    version: 1,
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

  return { parameters, peer };
};

const unusedTransport: TransportLayerFunction = {
  transportId: "wrtc",
  create: () => { throw new Error("Transport creation is not reached"); },
};

it("classifies inconsistent saved key material as deterministic invalid state", async () => {
  const { parameters } = await createSavedState();

  parameters.h = "0".repeat(16);

  await expect(
    createSession(parameters, [unusedTransport], async () => ({}), {
      onConnectionParametersChange: () => {},
    }),
  ).rejects.toBeInstanceOf(InvalidSavedSessionError);
});

it("rejects resumption without a synchronous persistence callback", async () => {
  const { parameters } = await createSavedState();

  await expect(createSession(parameters, [unusedTransport], async () => ({})))
    .rejects.toThrow("Resuming a saved session requires durable connection parameter persistence");
});

it("keeps saved state when its persisted transport is unavailable", async () => {
  const { parameters, peer } = await createSavedState();
  const [signalStatus, setSignalStatus] = observable<SignalingStatus>(SignalingStatus.STANDBY);
  const [peerKey, setPeerKey] = observable<typeof peer.encryptionKey | undefined>(undefined);
  const [peerCapabilities] = observable<PeerCapabilities | undefined>({ transports: ["wrtc"] });
  const signal = Object.assign(new EventEmitter(), {
    status: signalStatus,
    peerKey,
    peerCapabilities,
    setup: async () => {
      setPeerKey(peer.encryptionKey);
      setSignalStatus(SignalingStatus.ENCRYPTED);
    },
    resume: async () => {},
    teardown: vi.fn(async () => {}),
    send: vi.fn(async () => {}),
  }) as unknown as SignalingLayer;

  const createSignal = async () => signal;

  loadSignaling.mockResolvedValue(async () => createSignal);
  parameters.transportId = "unsupported";

  const session = await createSession(
    parameters,
    [unusedTransport],
    async () => ({}),
    { onConnectionParametersChange: () => {} },
  );
  const closed = new Promise<{ reason: string | undefined; isPairingInvalidated: boolean; }>((resolve) => {
    session.emitter.once("close", (reason, isPairingInvalidated) => {
      resolve({ reason, isPairingInvalidated });
    });
  });

  try {
    await session.connect();
  }
  catch {
    // Terminal closure below describes the failure regardless of setup timing.
  }

  await expect(closed).resolves.toEqual({
    reason: "No common transport with peer",
    isPairingInvalidated: false,
  });
});
