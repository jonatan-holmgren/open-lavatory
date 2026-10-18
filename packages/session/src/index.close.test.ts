import { observable } from "@openlv/core";
import type { EncryptionKey } from "@openlv/core/encryption";
import { EventEmitter } from "eventemitter3";
import {
  Status as SignalingStatus,
  type PeerCapabilities,
  type SignalingLayer,
} from "@openlv/signaling";
import {
  Status as TransportStatus,
  type TransportLayerFunction,
} from "@openlv/transport";
import { describe, expect, it, vi } from "vitest";

const { loadSignaling } = vi.hoisted(() => ({ loadSignaling: vi.fn() }));

vi.mock("./dynamic.js", () => ({
  loadSignaling,
  loadTransport: vi.fn(),
}));

import { createSession, SessionStatus } from "./index.js";

const createConnectedSession = async () => {
  const sent: object[] = [];
  const teardownTransport = vi.fn(async () => {});
  let receive: ((message: { type: string; payload?: unknown; messageId?: string; }) => void) | undefined;

  const [transportStatus, setTransportStatus] = observable<TransportStatus>(TransportStatus.STANDBY);
  const [signalStatus, setSignalStatus] = observable<SignalingStatus>(SignalingStatus.STANDBY);
  const [peerKey, setPeerKey] = observable<EncryptionKey | undefined>(undefined);
  const [peerCapabilities] = observable<PeerCapabilities | undefined>({ transports: ["wrtc"] });
  const publicKey = {
    toString: () => "pinned-peer",
    encrypt: async () => "",
  } as EncryptionKey;
  const signaling = Object.assign(new EventEmitter(), {
    status: signalStatus,
    peerKey,
    peerCapabilities,
    setup: async () => {
      setPeerKey(publicKey);
      setSignalStatus(SignalingStatus.ENCRYPTED);
    },
    resume: async () => {},
    teardown: vi.fn(async () => {}),
    send: vi.fn(async () => {}),
  }) as unknown as SignalingLayer;

  loadSignaling.mockImplementation(async () => async () => async () => signaling);

  const transport: TransportLayerFunction = {
    transportId: "wrtc",
    create: (parameters) => {
      receive = parameters.onmessage;

      return {
        type: "wrtc",
        setup: async () => { setTransportStatus(TransportStatus.CONNECTED); },
        renegotiate: async () => {},
        teardown: teardownTransport,
        send: async (message) => { sent.push(message); },
        handle: async () => {},
        emitter: new EventEmitter(),
        status: transportStatus,
      };
    },
  };

  const session = await createSession(
    { p: "ntfy", s: "https://ntfy.sh/" },
    [transport],
    async () => ({}),
  );

  await session.connect();
  await session.status.until(status => status === SessionStatus.CONNECTED);

  return { session, sent, receive, teardownTransport };
};

describe("session close envelope", () => {
  it("sends an unacknowledged close before local teardown", async () => {
    const { session, sent, teardownTransport } = await createConnectedSession();

    await session.close();

    expect(sent).toEqual([{ type: "close" }]);
    expect(teardownTransport).toHaveBeenCalledOnce();
    expect(session.status.get()).toBe(SessionStatus.DISCONNECTED);
  });

  it("tears down on a received close without sending an acknowledgement", async () => {
    const { session, sent, receive, teardownTransport } = await createConnectedSession();

    receive?.({ type: "close" });
    await session.status.until(status => status === SessionStatus.DISCONNECTED);

    expect(sent).toEqual([]);
    expect(teardownTransport).toHaveBeenCalledOnce();
  });
});
