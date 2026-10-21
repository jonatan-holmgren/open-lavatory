import { observable } from "@openlv/core";
import type { EncryptionKey } from "@openlv/core/encryption";
import {
  type PeerCapabilities,
  type SignalingLayer,
  Status as SignalingStatus,
} from "@openlv/signaling";
import {
  Status as TransportStatus,
  type TransportLayerFunction,
} from "@openlv/transport";
import { EventEmitter } from "eventemitter3";
import { describe, expect, it, vi } from "vitest";

const { loadSignaling } = vi.hoisted(() => ({ loadSignaling: vi.fn() }));

vi.mock("./dynamic.js", () => ({
  loadSignaling,
  loadTransport: vi.fn(),
}));

import { createSession, SessionStatus } from "./index.js";

const createConnectedSession = async (options: {
  setup?: () => Promise<void>;
  teardown?: () => Promise<void>;
} = {}) => {
  const sent: object[] = [];
  const teardownTransport = vi.fn(async () => {
    await options.teardown?.();
  });
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

  const createSignal = async () => signaling;

  loadSignaling.mockResolvedValue(async () => createSignal);

  const transport: TransportLayerFunction = {
    transportId: "wrtc",
    create: (parameters) => {
      receive = parameters.onmessage;

      return {
        type: "wrtc",
        setup: async () => {
          await options.setup?.();
          setTransportStatus(TransportStatus.CONNECTED);
        },
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

  return { session, signaling, sent, receive, teardownTransport, setTransportStatus };
};

describe("session close envelope", () => {
  it("sends an unacknowledged close before local teardown", async () => {
    const { session, sent, teardownTransport } = await createConnectedSession();

    const closed = vi.fn();

    session.emitter.on("close", closed);
    await session.close();

    expect(sent).toEqual([{ type: "close" }]);
    expect(teardownTransport).toHaveBeenCalledOnce();
    expect(session.status.get()).toBe(SessionStatus.DISCONNECTED);
    await session.close({ notifyPeer: false });
    expect(closed).toHaveBeenCalledExactlyOnceWith(undefined, false);
  });

  it("tears down on a received close without sending an acknowledgement", async () => {
    const { session, sent, receive, teardownTransport } = await createConnectedSession();

    receive?.({ type: "close" });
    await session.close({ notifyPeer: false });

    expect(sent).toEqual([]);
    expect(teardownTransport).toHaveBeenCalledOnce();
  });

  it("keeps transport interruptions recoverable without emitting terminal closure", async () => {
    const { session, signaling, setTransportStatus } = await createConnectedSession();
    const closed = vi.fn();

    session.emitter.on("close", closed);
    setTransportStatus(TransportStatus.ERROR);
    expect(session.status.get()).toBe(SessionStatus.DISCONNECTED);
    expect(closed).not.toHaveBeenCalled();

    signaling.emit("resume");
    await session.status.until(status => status === SessionStatus.CONNECTED);
    expect(closed).not.toHaveBeenCalled();
    await session.close({ notifyPeer: false });
    expect(closed).toHaveBeenCalledExactlyOnceWith(undefined, false);
  });

  it.each(["setup", "teardown"])("does not revive a closed transport during pending %s", async (phase) => {
    let release!: () => void;
    let started!: () => void;
    // eslint-disable-next-line unicorn/prefer-promise-with-resolvers -- Project libraries stop at ES2022.
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    // eslint-disable-next-line unicorn/prefer-promise-with-resolvers -- Project libraries stop at ES2022.
    const reached = new Promise<void>((resolve) => {
      started = resolve;
    });
    let isRestarting = false;
    let isActive = false;
    const pause = async (currentPhase: string) => {
      if (!isRestarting || currentPhase !== phase) return;

      isRestarting = false;
      started();
      await blocked;
    };
    const { session, signaling } = await createConnectedSession({
      setup: async () => {
        await pause("setup");
        isActive = true;
      },
      teardown: async () => {
        await pause("teardown");
        isActive = false;
      },
    });

    isRestarting = true;
    signaling.emit("resume");
    await reached;
    const closing = session.close({ notifyPeer: false });

    release();
    await closing;
    expect(isActive).toBe(false);
    expect(session.status.get()).toBe(SessionStatus.DISCONNECTED);
  });
});
