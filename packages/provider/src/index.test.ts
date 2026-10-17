/* eslint-disable max-lines -- Race coverage belongs with the provider behavior it guards. */
import { observable, type SessionConnectionParameters } from "@openlv/core";
import type * as SessionModule from "@openlv/session";
import { createSession, type Session, SessionStatus } from "@openlv/session";
import { Status as SignalStatus } from "@openlv/signaling";
import { describe, expect, test, vi } from "vitest";

import { createProvider, ProviderStatus } from "./index.js";

vi.mock("@openlv/session", async (importOriginal) => {
  const actual = await importOriginal<typeof SessionModule>();

  return { ...actual, createSession: vi.fn() };
});

const parameters: SessionConnectionParameters = {
  version: 1,
  sessionId: "abcdefghijklmnop",
  h: "0123456789abcdef",
  k: "0123456789abcdef0123456789abcdef",
  p: "ntfy",
  s: "https://ntfy.sh/",
  relyingPublicKey: "peer",
  encryptionKey: "public",
  decryptionKey: "private",
  pairingId: "abcdefghijklmnop",
  transportId: "wrtc",
  lastCounter: 0,
  lastSeenCounter: 0,
  lastSeenAckCounter: 0,
};

const createMemoryStorage = (): Storage => {
  const values = new Map<string, string>();

  return {
    get length() { return values.size; },
    clear: () => values.clear(),
    getItem: key => values.get(key) ?? null,
    key: index => Array.from(values.keys())[index] ?? null,
    removeItem: (key) => { values.delete(key); },
    setItem: (key, value) => { values.set(key, value); },
  };
};


const createPeerSession = (connectError?: string, hasSignalingError = true, isPairingInvalidated = false) => {
  const [status, setStatus] = observable<SessionStatus>(SessionStatus.CREATED);
  const [error, setError] = observable<string | undefined>(undefined);
  const [signalStatus, setSignalStatus] = observable<SignalStatus>(SignalStatus.READY);
  let isPairingInvalidatedState = isPairingInvalidated;
  const fail = (reason: string, shouldInvalidatePairing = false) => {
    isPairingInvalidatedState ||= shouldInvalidatePairing;
    setError(reason);

    if (hasSignalingError) setSignalStatus(SignalStatus.ERROR);

    setStatus(SessionStatus.DISCONNECTED);
  };
  const session: Partial<Session> = {
    status,
    error,
    signalStatus,
    _internal: { transport: undefined, get isPairingInvalidated() { return isPairingInvalidatedState; } } as Session["_internal"],
    connect: async () => {
      if (connectError) fail(connectError);
      else setStatus(SessionStatus.CONNECTED);
    },
    close: async () => { setStatus(SessionStatus.DISCONNECTED); },
    getHandshakeParameters: () => parameters,
    getConnectionParameters: () => parameters,
    send: async (request: object) => ({
      result: "method" in request && request.method === "eth_accounts" ? ["0x1234"] : "0x1",
    }),
  };

  return { session: session as Session, fail, disconnect: () => setStatus(SessionStatus.DISCONNECTED) };
};

const createRestorableProvider = (peer = createPeerSession(), storage = createMemoryStorage()) => {
  const provider = createProvider({ storage });

  provider.storage.setSession(parameters);
  vi.mocked(createSession).mockResolvedValueOnce(peer.session);

  return provider;
};

describe("provider auto restore", () => {
  test("connected sessions persist and auto-restore by default", async () => {
    const io = createMemoryStorage();
    const provider = createProvider({ storage: io });

    vi.mocked(createSession).mockResolvedValueOnce(createPeerSession().session);
    await provider.createSession(parameters);

    expect(provider.storage.getSettings().autoReconnect).toBe(true);
    expect(provider.storage.getSession()).toEqual(parameters);

    const restoredPeer = createPeerSession();

    vi.mocked(createSession).mockClear()
      .mockResolvedValueOnce(restoredPeer.session);
    const restored = createProvider({ storage: io });

    await restored.status.until(status => status === ProviderStatus.CONNECTED);
    expect(restored.session.get()).toBe(restoredPeer.session);
  });
});

describe("provider saved pairing failures", () => {
  test.each([
    "Resume failed: peer key mismatch; re-pair using a fresh openlv:// URI",
    "Resume-confirm proof is invalid; re-pair through a fresh openlv:// URI",
    "Resume-ack challenge mismatch; re-pair through a fresh openlv:// URI",
    "Resume counter did not advance; re-pair through a fresh openlv:// URI",
    "Signaling authentication failed: failed to decrypt; pair again",
    "Received client public key does not match saved pairing; pair again",
    "Failed to parse received host public key; pair again",
  ])("a rejected authentication deletes the pairing and prevents retry: %s", async (reason) => {
    const provider = createRestorableProvider(createPeerSession(reason, true, true));

    await expect(provider.restoreSession()).rejects.toThrow(reason);

    expect(provider.error.get()).toBe(reason);
    expect(provider.status.get()).toBe(ProviderStatus.ERROR);
    expect(provider.session.get()).toBeUndefined();
    expect(provider.storage.getSession()).toBeUndefined();
    await expect(provider.restoreSession()).rejects.toThrow("No saved session to restore");
  });
});

test.each([
  ["Network disconnected", true],
  ["Signaling failed or timed out", true],
] as const)("a transient network failure preserves counters for retry: %s", async (reason, signalingError) => {
  const peer = createPeerSession(reason, signalingError);
  const retryPeer = createPeerSession();
  const provider = createRestorableProvider(peer);
  const advanced = { ...parameters, lastCounter: 1, lastSeenCounter: 2, lastSeenAckCounter: 3 };
  const retried = { ...advanced, lastCounter: 2 };
  const failedConnect = peer.session.connect;
  const retryConnect = retryPeer.session.connect;

  peer.session.connect = async () => {
    vi.mocked(createSession).mock.lastCall?.[3]?.onConnectionParametersChange?.(advanced);
    await failedConnect();
  };
  retryPeer.session.connect = async () => {
    vi.mocked(createSession).mock.lastCall?.[3]?.onConnectionParametersChange?.(retried);
    await retryConnect();
  };
  retryPeer.session.getConnectionParameters = () => retried;
  provider.storage.setSettings({ ...provider.storage.getSettings(), autoReconnect: false });
  await expect(provider.restoreSession()).rejects.toThrow(reason);

  expect(provider.error.get()).toBe(reason);
  expect(provider.status.get()).toBe(ProviderStatus.ERROR);
  expect(provider.session.get()).toBeUndefined();
  expect(provider.storage.getSession()).toEqual(advanced);

  vi.mocked(createSession).mockResolvedValueOnce(retryPeer.session);
  await expect(provider.restoreSession()).resolves.toBe(retryPeer.session);

  expect(vi.mocked(createSession).mock.lastCall?.[0]).toEqual(advanced);
  expect(provider.status.get()).toBe(ProviderStatus.CONNECTED);
  expect(provider.storage.getSession()).toEqual(retried);
});


test.each(["eth_accounts", "eth_chainId"])(
  "a timed-out %s readiness probe tears down locally and retries the newest saved counters",
  async (method) => {
    const peer = createPeerSession();
    const provider = createRestorableProvider(peer);
    const retryPeer = createPeerSession();
    const advanced = { ...parameters, lastCounter: 4, lastSeenCounter: 5, lastSeenAckCounter: 6 };
    const reason = "Request timed out: remote peer did not acknowledge";
    const send = peer.session.send;
    const onConnect = vi.fn();

    peer.session.close = vi.fn(peer.session.close);
    peer.session.send = async (request) => {
      if ("method" in request && request.method === method) {
        vi.mocked(createSession).mock.lastCall?.[3]?.onConnectionParametersChange?.(advanced);

        throw new Error(reason);
      }

      return await send(request);
    };
    retryPeer.session.getConnectionParameters = () => advanced;
    provider.on("connect", onConnect);
    await expect(provider.restoreSession()).rejects.toThrow(reason);

    expect(peer.session.close).toHaveBeenCalledExactlyOnceWith({ notifyPeer: false });
    expect(provider.session.get()).toBeUndefined();
    expect(provider.status.get()).toBe(ProviderStatus.ERROR);
    expect(provider.error.get()).toBe(reason);
    expect(provider.storage.getSession()).toEqual(advanced);
    expect(onConnect).not.toHaveBeenCalled();

    vi.mocked(createSession).mockResolvedValueOnce(retryPeer.session);
    await expect(provider.restoreSession()).resolves.toBe(retryPeer.session);

    expect(vi.mocked(createSession).mock.lastCall?.[0]).toEqual(advanced);
    expect(provider.status.get()).toBe(ProviderStatus.CONNECTED);
    expect(onConnect).toHaveBeenCalledOnce();
  },
);

