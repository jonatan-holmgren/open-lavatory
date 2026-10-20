import { observable, type SerializedEncryptionKey } from "@openlv/core";
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

const createSignalingLoader = (signaling: SignalingLayer) => {
  const createSignal = async () => signaling;
  const createChannel = async () => createSignal;

  return async () => createChannel;
};

import { createSession } from "./index.js";

it("keeps saved state when its persisted transport is unavailable", async () => {
  const local = await generateKeyPair();
  const peer = await generateKeyPair();
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

  loadSignaling.mockImplementation(createSignalingLoader(signal));

  const unusedTransport: TransportLayerFunction = {
    transportId: "wrtc",
    create: () => { throw new Error("The persisted transport is unavailable"); },
  };
  const savedParameters = {
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
    transportId: "unsupported",
    lastCounter: 1,
    lastSeenCounter: 1,
    lastSeenAckCounter: 1,
  };
  const session = await createSession(
    savedParameters,
    [unusedTransport],
    async () => ({}),
    { onConnectionParametersChange: () => {} },
  );

  await expect(session.connect()).rejects.toThrow("No common transport with peer");
  expect(session._internal.isPairingInvalidated).toBe(false);
});
