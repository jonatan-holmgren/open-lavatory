import { observable, type SerializedEncryptionKey, type SessionConnectionParameters } from "@openlv/core";
import { generateKeyPair, hashPublicKey } from "@openlv/core/encryption";
import {
  type SignalingHooks,
  type SignalingLayer,
  Status as SignalingStatus,
} from "@openlv/signaling";
import type { TransportLayerFunction } from "@openlv/transport";
import { EventEmitter } from "eventemitter3";
import { describe, expect, it, vi } from "vitest";

const { loadSignaling } = vi.hoisted(() => ({ loadSignaling: vi.fn() }));

vi.mock("./dynamic.js", () => ({
  loadSignaling,
  loadTransport: vi.fn(),
}));

import { createSession, InvalidSavedSessionError } from "./index.js";

const transport: TransportLayerFunction = {
  transportId: "wrtc",
  create: () => {
    throw new Error("Transport creation is not reached");
  },
};

const createParameters = async (
  role: "host" | "joining",
): Promise<SessionConnectionParameters> => {
  const local = await generateKeyPair();
  const peer = await generateKeyPair();

  return {
    version: 1,
    sessionId: "mytestsession111",
    h: await hashPublicKey(role === "host" ? local.encryptionKey : peer.encryptionKey),
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
    peerCapabilities: {
      transports: ["wrtc"],
      info: { identity: "com.example.wallet", name: "Wallet" },
    },
  };
};

const createSessionWithHooks = async (
  parameters: SessionConnectionParameters,
): Promise<SignalingHooks> => {
  const [status] = observable(SignalingStatus.STANDBY);
  const [peerKey] = observable(undefined);
  const [peerCapabilities] = observable(undefined);
  const signal = Object.assign(new EventEmitter(), {
    status,
    peerKey,
    peerCapabilities,
    setup: async () => {},
    resume: async () => {},
    teardown: async () => {},
    send: async () => {},
  }) as unknown as SignalingLayer;
  let captured: SignalingHooks | undefined;
  const signaling = async (hooks: SignalingHooks) => {
    captured = hooks;

    return signal;
  };
  const signalLayer = async () => signaling;

  loadSignaling.mockResolvedValue(signalLayer);

  await createSession(parameters, [transport], async () => ({}), {
    onConnectionParametersChange: () => {},
  });

  if (!captured) throw new Error("Signaling hooks were not captured");

  return captured;
};

describe("saved session resumption role", () => {
  it("lets either side initiate so a one-sided reload can recover", async () => {
    const joining = await createSessionWithHooks(await createParameters("joining"));
    const host = await createSessionWithHooks(await createParameters("host"));

    expect(joining.resume?.initiate).toBe(true);
    expect(host.resume?.initiate).toBe(true);
  });

  it("seeds saved peer capabilities for the resumed transport", async () => {
    const parameters = await createParameters("joining");
    const hooks = await createSessionWithHooks(parameters);

    expect(hooks.initialPeerCapabilities).toEqual(parameters.peerCapabilities);
  });

  it("classifies inconsistent saved key material as deterministic invalid state", async () => {
    const parameters = await createParameters("joining");

    parameters.h = "0".repeat(16);

    await expect(
      createSession(parameters, [transport], async () => ({}), {
        onConnectionParametersChange: () => {},
      }),
    ).rejects.toBeInstanceOf(InvalidSavedSessionError);
  });
});
