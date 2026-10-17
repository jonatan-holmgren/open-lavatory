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

const deferred = <T>() => {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  // eslint-disable-next-line unicorn/prefer-promise-with-resolvers -- Project libraries stop at ES2022.
  const promise = new Promise<T>((resolve_, reject_) => {
    resolve = resolve_;
    reject = reject_;
  });

  return { promise, resolve, reject };
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

describe("provider saved pairing counters", () => {
  test("explicit restores persist connection updates with auto reconnect disabled", async () => {
    const provider = createRestorableProvider();
    const updated = { ...parameters, lastCounter: 1 };

    provider.storage.setSettings({ ...provider.storage.getSettings(), autoReconnect: false });
    await provider.restoreSession();
    vi.mocked(createSession).mock.lastCall?.[3]?.onConnectionParametersChange?.(updated);

    expect(provider.storage.getSettings().autoReconnect).toBe(false);
    expect(provider.storage.getSession()).toEqual(updated);
  });

  test.each([false, true])(
    "disabled auto reconnect leaves unrelated saved state unchanged (saved pairing: %s)",
    async (hasSavedPairing) => {
      const provider = createProvider({ storage: createMemoryStorage() });
      const peer = createPeerSession();
      const saved = hasSavedPairing
        ? { ...parameters, pairingId: "different-pairing" }
        : undefined;

      provider.storage.setSettings({ ...provider.storage.getSettings(), autoReconnect: false });

      if (saved) provider.storage.setSession(saved);

      vi.mocked(createSession).mockResolvedValueOnce(peer.session);
      await provider.createSession(parameters);
      vi.mocked(createSession).mock.lastCall?.[3]?.onConnectionParametersChange?.({
        ...parameters,
        lastCounter: 1,
      });

      expect(provider.storage.getSession()).toEqual(saved);
    },
  );

  test.each(["read", "write"] as const)(
    "saved pairing storage %s failures propagate from connection updates",
    async (operation) => {
      const io = createMemoryStorage();
      const provider = createRestorableProvider(createPeerSession(), io);
      const failure = new Error(`storage ${operation} failed`);

      provider.storage.setSettings({ ...provider.storage.getSettings(), autoReconnect: false });
      await provider.restoreSession();
      const update = vi.mocked(createSession).mock.lastCall?.[3]?.onConnectionParametersChange;

      const storageMethod = operation === "read" ? "getItem" : "setItem";

      vi.spyOn(io, storageMethod).mockImplementation(() => {
        throw failure;
      });

      expect(() => update?.({ ...parameters, lastCounter: 1 })).toThrow(failure);
    },
  );

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
  ["Authenticated resume timed out", true, true],
  ["Authenticated resume timed out awaiting proof", true, true],
  ["Session resumption timed out. Request a fresh pairing URI and try again.", false, true],
])("a resume deadline expiry invalidates the pairing: %s", async (reason, hasSignalingError, shouldInvalidatePairing) => {
  const provider = createRestorableProvider(createPeerSession(reason, hasSignalingError, shouldInvalidatePairing));

  await expect(provider.restoreSession()).rejects.toThrow(reason);

  expect(provider.storage.getSession()).toBeUndefined();
  await expect(provider.restoreSession()).rejects.toThrow("No saved session to restore");
});

test.each([
  [undefined, false, false],
  ["Network disconnected", false, false],
  ["Resume-confirm proof is invalid", false, true],
  ["Resume-confirm proof is invalid", true, true],
  ["Authenticated resume timed out", false, true],
  ["Session resumption timed out. Request a fresh pairing URI and try again.", false, true],
] as const)("a live session ends with %s (transport disconnected first: %s)", async (reason, disconnectedFirst, shouldInvalidatePairing) => {
  const peer = createPeerSession();
  const provider = createRestorableProvider(peer);
  const onDisconnect = vi.fn();

  peer.session._internal = {
    transport: disconnectedFirst ? {} as Session["_internal"]["transport"] : undefined,
    get isPairingInvalidated() { return shouldInvalidatePairing; },
  } as Session["_internal"];
  provider.on("disconnect", onDisconnect);
  await provider.restoreSession();
  expect(provider.status.get()).toBe(ProviderStatus.CONNECTED);

  if (disconnectedFirst) {
    peer.disconnect();
    expect(provider.storage.getSession()).toEqual(parameters);
  }

  if (reason) peer.fail(reason, shouldInvalidatePairing);
  else peer.disconnect();

  expect(provider.error.get()).toBe(reason);
  expect(provider.status.get()).toBe(reason ? ProviderStatus.ERROR : ProviderStatus.STANDBY);
  expect(provider.session.get()).toBeUndefined();
  expect(provider.storage.getSession()).toEqual(!reason || shouldInvalidatePairing ? undefined : parameters);
  expect(onDisconnect).toHaveBeenCalledOnce();
  expect(onDisconnect.mock.calls[0]?.[0]).toMatchObject({ code: 4900 });

  if (!reason || shouldInvalidatePairing) await expect(provider.restoreSession()).rejects.toThrow("No saved session to restore");
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

test("explicit close clears saved pairing after a transient failed restore", async () => {
  const provider = createRestorableProvider(createPeerSession("Network disconnected"));

  await expect(provider.restoreSession()).rejects.toThrow("Network disconnected");
  await provider.closeSession();

  expect(provider.status.get()).toBe(ProviderStatus.STANDBY);
  expect(provider.error.get()).toBeUndefined();
  expect(provider.storage.getSession()).toBeUndefined();
});

test.each([false, true])("explicit close clears saved pairing even when teardown fails: %s", async (closeFails) => {
  const peer = createPeerSession();
  const provider = createRestorableProvider(peer);

  await provider.restoreSession();

  if (closeFails) {
    peer.session.close = async () => {
      throw new Error("Session teardown failed");
    };

    await expect(provider.closeSession()).rejects.toThrow("Session teardown failed");
  }
  else {
    await provider.closeSession();
  }

  expect(provider.status.get()).toBe(ProviderStatus.STANDBY);
  expect(provider.session.get()).toBeUndefined();
  expect(provider.storage.getSession()).toBeUndefined();
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

test("concurrent restore and account callers await account and chain readiness", async () => {
  const io = createMemoryStorage();
  const saved = createProvider({ storage: io });

  saved.storage.setSession(parameters);
  const peer = createPeerSession();
  const accountsResponse = deferred<object>();
  const chainResponse = deferred<object>();
  const accountsRequested = deferred<void>();
  const chainRequested = deferred<void>();

  peer.session.send = vi.fn(peer.session.send)
    .mockImplementationOnce(() => {
      accountsRequested.resolve();

      return accountsResponse.promise;
    })
    .mockImplementationOnce(() => {
      chainRequested.resolve();

      return chainResponse.promise;
    });
  vi.mocked(createSession).mockClear()
    .mockResolvedValueOnce(peer.session);

  const provider = createProvider({ storage: io });
  const connected = vi.fn();
  const accountsChanged = vi.fn();

  provider.on("connect", connected);
  provider.on("accountsChanged", accountsChanged);
  let isSettled = false;
  const restoration = (async () => {
    const restored = await provider.restoreSession();

    isSettled = true;

    return restored;
  })();
  const otherRestoration = provider.restoreSession();
  const accounts = provider.request({ method: "eth_requestAccounts" });
  const existingAccounts = provider.request({ method: "eth_accounts" });

  await accountsRequested.promise;
  expect(provider.status.get()).toBe(ProviderStatus.CONNECTING);
  expect(isSettled).toBe(false);
  accountsResponse.resolve({ result: ["0x1234"] });
  await chainRequested.promise;
  expect(provider.status.get()).toBe(ProviderStatus.CONNECTING);
  expect(isSettled).toBe(false);
  expect(connected).not.toHaveBeenCalled();
  expect(accountsChanged).not.toHaveBeenCalled();
  chainResponse.resolve({ result: "0x2a" });

  await expect(Promise.all([restoration, otherRestoration, accounts, existingAccounts])).resolves.toEqual([
    peer.session, peer.session, ["0x1234"], ["0x1234"],
  ]);
  expect(provider.status.get()).toBe(ProviderStatus.CONNECTED);
  expect(connected).toHaveBeenCalledExactlyOnceWith({ chainId: "0x2a" });
  expect(accountsChanged).toHaveBeenCalledExactlyOnceWith(["0x1234"]);
});

test("a synchronous CREATING subscriber joins the existing restoration", async () => {
  const provider = createRestorableProvider();
  const connected = vi.fn();
  let hasReentered = false;
  let reentrant: Promise<Session> | undefined;

  provider.on("connect", connected);
  const unsubscribe = provider.status.subscribe((status) => {
    if (hasReentered || status !== ProviderStatus.CREATING) return;

    hasReentered = true;
    reentrant = provider.restoreSession();
  });

  const restored = await provider.restoreSession();

  unsubscribe();
  expect(hasReentered).toBe(true);
  await expect(reentrant).resolves.toBe(restored);
  expect(provider.session.get()).toBe(restored);
  expect(connected).toHaveBeenCalledOnce();
});

test.each(["deferred restore", "construction", "eth_accounts", "eth_chainId"] as const)(
  "explicit close cancels pending %s without stale publication",
  async (stage) => {
    const provider = createProvider({ storage: createMemoryStorage() });
    const peer = createPeerSession();
    const entered = deferred<void>();
    const completion = deferred<Session | object>();
    const connected = vi.fn();
    const send = peer.session.send;

    peer.session.close = vi.fn(peer.session.close);
    peer.session.send = async (request) => {
      if ("method" in request && request.method === stage) {
        entered.resolve();

        return await completion.promise as object;
      }

      return await send(request);
    };
    vi.mocked(createSession).mockClear()
      .mockImplementationOnce(async () => {
        if (stage !== "construction") return peer.session;

        entered.resolve();

        return await completion.promise as Session;
      });
    provider.on("connect", connected);
    provider.storage.setSession(parameters);
    const restoration = expect(provider.restoreSession()).rejects.toThrow();

    if (stage !== "deferred restore") await entered.promise;

    const update = vi.mocked(createSession).mock.lastCall?.[3]?.onConnectionParametersChange;

    await provider.closeSession();
    update?.({ ...parameters, lastCounter: 9 });

    if (stage === "construction") completion.resolve(peer.session);
    else if (stage !== "deferred restore") completion.reject(new Error("Readiness probe failed"));

    await restoration;

    if (stage === "deferred restore") expect(createSession).not.toHaveBeenCalled();
    else expect(peer.session.close).toHaveBeenCalledWith({ notifyPeer: false });

    expect(provider.session.get()).toBeUndefined();
    expect(provider.status.get()).toBe(ProviderStatus.STANDBY);
    expect(provider.error.get()).toBeUndefined();
    expect(provider.storage.getSession()).toBeUndefined();
    expect(connected).not.toHaveBeenCalled();
    vi.mocked(createSession).mockReset();
  },
);

test("a newer session survives an older close and readiness completion", async () => {
  const provider = createProvider({ storage: createMemoryStorage() });
  const oldPeer = createPeerSession();
  const nextPeer = createPeerSession();
  const requested = deferred<void>();
  const accounts = deferred<object>();
  const teardown = deferred<void>();
  const connected = vi.fn();

  oldPeer.session.send = async () => {
    requested.resolve();

    return await accounts.promise;
  };
  oldPeer.session.close = vi.fn(async () => {
    await teardown.promise;
  });
  vi.mocked(createSession).mockResolvedValueOnce(oldPeer.session)
    .mockResolvedValueOnce(nextPeer.session);
  provider.on("connect", connected);
  const oldStart = expect(provider.createSession(parameters)).rejects.toThrow("canceled");

  await requested.promise;
  const update = vi.mocked(createSession).mock.lastCall?.[3]?.onConnectionParametersChange;
  const closing = provider.closeSession();

  await provider.createSession(parameters);
  teardown.resolve();
  await closing;
  accounts.resolve({ result: ["0xdead"] });
  await oldStart;
  update?.({ ...parameters, lastCounter: 9 });
  expect(provider.session.get()).toBe(nextPeer.session);
  expect(provider.status.get()).toBe(ProviderStatus.CONNECTED);
  expect(provider.error.get()).toBeUndefined();
  expect(provider.storage.getSession()).toEqual(parameters);
  expect(connected).toHaveBeenCalledOnce();
});
