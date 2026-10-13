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

const createPeerSession = (connectError?: string) => {
  const [status, setStatus] = observable<SessionStatus>(SessionStatus.CREATED);
  const [error, setError] = observable<string | undefined>(undefined);
  const [signalStatus, setSignalStatus] = observable<SignalStatus>(SignalStatus.READY);
  const fail = (reason: string) => {
    setError(reason);
    setSignalStatus(SignalStatus.ERROR);
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

  return { session: session as Session, fail };
};

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
