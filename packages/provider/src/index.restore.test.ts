import { observable } from "@openlv/core";
import { EventEmitter } from "eventemitter3";
import { afterEach, describe, expect, it, vi } from "vitest";

const { createSessionMock } = vi.hoisted(() => ({ createSessionMock: vi.fn() }));

vi.mock("@openlv/session", () => ({
  createSession: createSessionMock,
  SessionStatus: {
    CREATED: "created",
    SIGNALING: "signaling",
    READY: "ready",
    LINKING: "linking",
    CONNECTED: "connected",
    DISCONNECTED: "disconnected",
  },
}));

import { createProvider, ProviderStatus } from "./index.js";
import { createProviderStorage } from "./storage/index.js";

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
};

const createStorage = () => {
  const values = new Map<string, string>();

  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); },
    removeItem: (key: string) => { values.delete(key); },
    clear: () => values.clear(),
    key: (index: number) => {
      let current = 0;

      for (const key of values.keys()) {
        if (current === index) return key;

        current++;
      }

      return null;
    },
    get length() { return values.size; },
  } as Storage;
};

const createReadySession = () => {
  const [status, setStatus] = observable("created");
  const [signalStatus] = observable("encrypted");

  return {
    status,
    signalStatus,
    error: observable<string | undefined>(undefined)[0],
    peerInfo: observable(undefined)[0],
    getHandshakeParameters: () => ({ version: 1, sessionId: "session-id", h: "hash", k: "key", p: "ntfy", s: "https://ntfy.sh/" }),
    getConnectionParameters: () => savedParameters,
    connect: async () => { setStatus("connected"); },
    close: async () => {},
    send: async (message: { method: string; }) => {
      if (message.method === "eth_accounts") return { result: [] };

      return { result: "0x1" };
    },
    emitter: new EventEmitter(),
    _internal: { isPairingInvalidated: false, transport: {} },
  };
};

afterEach(() => createSessionMock.mockReset());

describe("provider automatic session restoration", () => {
  it("restores the stored pairing and reaches connected state on initialization", async () => {
    const backingStorage = createStorage();
    const seededStorage = createProviderStorage({ storage: backingStorage });

    seededStorage.setSession(savedParameters);
    const restored = createReadySession();

    createSessionMock.mockResolvedValue(restored);

    const provider = createProvider({ storage: backingStorage });

    await provider.status.until(status => status === ProviderStatus.CONNECTED);

    expect(createSessionMock).toHaveBeenCalledWith(
      savedParameters,
      expect.any(Array),
      expect.any(Function),
      expect.objectContaining({ onConnectionParametersChange: expect.any(Function) }),
    );
    expect(provider.session.get()).toBe(restored);
    expect(await provider.getAccounts()).toEqual([]);
  });

  it("clears a saved pairing when transport failure invalidates it", async () => {
    const backingStorage = createStorage();
    const seededStorage = createProviderStorage({ storage: backingStorage });

    seededStorage.setSettings({ ...seededStorage.getSettings(), autoReconnect: false });
    seededStorage.setSession(savedParameters);

    const failed = createReadySession();

    failed._internal.isPairingInvalidated = true;
    failed.connect = async () => {
      throw new Error("No common transport with peer");
    };
    createSessionMock.mockResolvedValue(failed);

    const provider = createProvider({ storage: backingStorage });

    await expect(provider.restoreSession()).rejects.toThrow("No common transport with peer");
    expect(provider.storage.getSession()).toBeUndefined();
  });
});
