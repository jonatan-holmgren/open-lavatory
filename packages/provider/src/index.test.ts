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

const createPeerSession = (connectError?: string, hasSignalingError = true) => {
  const [status, setStatus] = observable<SessionStatus>(SessionStatus.CREATED);
  const [error, setError] = observable<string | undefined>(undefined);
  const [signalStatus, setSignalStatus] = observable<SignalStatus>(SignalStatus.READY);
  const fail = (reason: string) => {
    setError(reason);

    if (hasSignalingError) setSignalStatus(SignalStatus.ERROR);

    setStatus(SessionStatus.DISCONNECTED);
  };
  const session: Partial<Session> = {
    status,
    error,
    signalStatus,
    connect: async () => {
      if (connectError) fail(connectError);
      else setStatus(SessionStatus.CONNECTED);
    },
    getHandshakeParameters: () => parameters,
    getConnectionParameters: () => parameters,
    send: async (request: object) => ({
      result: "method" in request && request.method === "eth_accounts" ? ["0x1234"] : "0x1",
    }),
  };

  return { session: session as Session, fail, disconnect: () => setStatus(SessionStatus.DISCONNECTED) };
};

describe("provider saved pairing counters", () => {
  test("explicit restores persist connection updates with auto reconnect disabled", async () => {
    const provider = createProvider({ storage: createMemoryStorage() });
    const peer = createPeerSession();
    const updated = { ...parameters, lastCounter: 1 };

    provider.storage.setSession(parameters);
    vi.mocked(createSession).mockResolvedValueOnce(peer.session);
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
      const provider = createProvider({ storage: io });
      const peer = createPeerSession();
      const failure = new Error(`storage ${operation} failed`);

      provider.storage.setSession(parameters);
      vi.mocked(createSession).mockResolvedValueOnce(peer.session);
      await provider.restoreSession();
      const update = vi.mocked(createSession).mock.lastCall?.[3]?.onConnectionParametersChange;

      if (operation === "read") {
        vi.spyOn(io, "getItem").mockImplementation(() => {
          throw failure;
        });
      }
      else {
        vi.spyOn(io, "setItem").mockImplementation(() => {
          throw failure;
        });
      }

      expect(() => update?.({ ...parameters, lastCounter: 1 })).toThrow(failure);
    },
  );
});

describe("provider saved pairing failures", () => {
  test("a rejected restore deletes the pairing and cannot return a failed session on retry", async () => {
    const reason = "Resume failed: peer key mismatch; re-pair using a fresh openlv:// URI";
    const peer = createPeerSession(reason);

    vi.mocked(createSession).mockResolvedValueOnce(peer.session);

    const provider = createProvider({ storage: createMemoryStorage() });

    provider.storage.setSession(parameters);
    await expect(provider.restoreSession()).rejects.toThrow(reason);

    expect(provider.error.get()).toBe(reason);
    expect(provider.status.get()).toBe(ProviderStatus.ERROR);
    expect(provider.session.get()).toBeUndefined();
    expect(provider.storage.getSession()).toBeUndefined();
    await expect(provider.restoreSession()).rejects.toThrow("No saved session to restore");
  });

  test("a failed resume on a live session invalidates its saved pairing too", async () => {
    const peer = createPeerSession();

    vi.mocked(createSession).mockResolvedValueOnce(peer.session);

    const provider = createProvider({ storage: createMemoryStorage() });

    provider.storage.setSession(parameters);
    await provider.restoreSession();
    expect(provider.status.get()).toBe(ProviderStatus.CONNECTED);

    const reason = "Resume failed: invalid proof; re-pair using a fresh openlv:// URI";

    peer.fail(reason);

    expect(provider.error.get()).toBe(reason);
    expect(provider.status.get()).toBe(ProviderStatus.ERROR);
    expect(provider.storage.getSession()).toBeUndefined();
    await expect(provider.restoreSession()).rejects.toThrow("No saved session to restore");
  });
});

test("an authentication failure invalidates a pairing after its transport disconnects", async () => {
  const peer = createPeerSession();
  const provider = createProvider({ storage: createMemoryStorage() });

  peer.session._internal = { transport: {} } as Session["_internal"];
  provider.storage.setSession(parameters);
  vi.mocked(createSession).mockResolvedValueOnce(peer.session);
  await provider.restoreSession();
  peer.disconnect();
  expect(provider.storage.getSession()).toEqual(parameters);

  const reason = "Resume failed: invalid proof";

  peer.fail(reason);
  expect(provider.error.get()).toBe(reason);
  expect(provider.session.get()).toBeUndefined();
  expect(provider.storage.getSession()).toBeUndefined();
});

test("a resume deadline invalidates saved state without a signaling error", async () => {
  const reason = "Session resumption timed out";
  const peer = createPeerSession(reason, false);
  const provider = createProvider({ storage: createMemoryStorage() });

  peer.session._internal = { transport: undefined } as Session["_internal"];
  provider.storage.setSession(parameters);
  vi.mocked(createSession).mockResolvedValueOnce(peer.session);
  await expect(provider.restoreSession()).rejects.toThrow(reason);

  expect(provider.error.get()).toBe(reason);
  expect(provider.session.get()).toBeUndefined();
  expect(provider.storage.getSession()).toBeUndefined();
});

test("concurrent restore and account callers await account and chain readiness", async () => {
  const io = createMemoryStorage();
  const saved = createProvider({ storage: io });

  saved.storage.setSession(parameters);
  saved.storage.setSettings({ ...saved.storage.getSettings(), autoReconnect: true });
  const peer = createPeerSession();
  let releaseAccounts!: (response: { result: string[]; }) => void;
  let releaseChain!: (response: { result: string; }) => void;
  let requestedAccounts!: () => void;
  let requestedChain!: () => void;
  // eslint-disable-next-line unicorn/prefer-promise-with-resolvers -- Project libraries stop at ES2022.
  const accountsRequested = new Promise<void>((resolve) => {
    requestedAccounts = resolve;
  });
  // eslint-disable-next-line unicorn/prefer-promise-with-resolvers -- Project libraries stop at ES2022.
  const chainRequested = new Promise<void>((resolve) => {
    requestedChain = resolve;
  });

  peer.session.send = vi.fn(peer.session.send)
    .mockImplementationOnce(() => {
      requestedAccounts();

      // eslint-disable-next-line unicorn/prefer-promise-with-resolvers -- Project libraries stop at ES2022.
      return new Promise((resolve) => {
        releaseAccounts = resolve;
      });
    })
    .mockImplementationOnce(() => {
      requestedChain();

      // eslint-disable-next-line unicorn/prefer-promise-with-resolvers -- Project libraries stop at ES2022.
      return new Promise((resolve) => {
        releaseChain = resolve;
      });
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
    const session = await provider.restoreSession();

    isSettled = true;

    return session;
  })();
  const otherRestoration = provider.restoreSession();
  const accounts = provider.request({ method: "eth_requestAccounts" });
  const existingAccounts = provider.request({ method: "eth_accounts" });

  await accountsRequested;
  expect(provider.status.get()).toBe(ProviderStatus.CONNECTING);
  expect(isSettled).toBe(false);
  releaseAccounts({ result: ["0x1234"] });
  await chainRequested;
  expect(provider.status.get()).toBe(ProviderStatus.CONNECTING);
  expect(isSettled).toBe(false);
  expect(connected).not.toHaveBeenCalled();
  expect(accountsChanged).not.toHaveBeenCalled();
  releaseChain({ result: "0x2a" });

  await expect(Promise.all([restoration, otherRestoration, accounts, existingAccounts])).resolves.toEqual([
    peer.session, peer.session, ["0x1234"], ["0x1234"],
  ]);
  expect(provider.status.get()).toBe(ProviderStatus.CONNECTED);
  expect(connected).toHaveBeenCalledExactlyOnceWith({ chainId: "0x2a" });
  expect(accountsChanged).toHaveBeenCalledExactlyOnceWith(["0x1234"]);
});

test("a synchronous CREATING subscriber joins the existing restoration", async () => {
  const provider = createProvider({ storage: createMemoryStorage() });
  const connected = vi.fn();
  let hasReentered = false;
  let reentrant: Promise<Session> | undefined;

  provider.storage.setSession(parameters);
  provider.on("connect", connected);
  vi.mocked(createSession).mockImplementation(async () => createPeerSession().session);
  const unsubscribe = provider.status.subscribe((status) => {
    if (hasReentered || status !== ProviderStatus.CREATING) return;

    hasReentered = true;
    reentrant = provider.restoreSession();
  });

  try {
    const restored = await provider.restoreSession();

    expect(hasReentered).toBe(true);
    await expect(reentrant).resolves.toBe(restored);
    expect(provider.session.get()).toBe(restored);
    expect(connected).toHaveBeenCalledOnce();
  }
  finally {
    unsubscribe();
    vi.mocked(createSession).mockReset();
  }
});
