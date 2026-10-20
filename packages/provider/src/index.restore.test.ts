import { observable, type SerializedEncryptionKey, type SessionConnectionParameters } from "@openlv/core";
import { generateKeyPair, hashPublicKey } from "@openlv/core/encryption";
import { EventEmitter } from "eventemitter3";
import { afterEach, describe, expect, it, vi } from "vitest";

const { createSessionMock, InvalidSavedSessionError } = vi.hoisted(() => {
  class InvalidSavedSessionError extends Error {}

  return { createSessionMock: vi.fn(), InvalidSavedSessionError };
});

vi.mock("@openlv/session", () => ({
  createSession: createSessionMock,
  InvalidSavedSessionError,
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

const createSavedParameters = async (): Promise<SessionConnectionParameters> => {
  const local = await generateKeyPair();
  const peer = await generateKeyPair();

  return {
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
    transportId: "wrtc",
    lastCounter: 1,
    lastSeenCounter: 1,
    lastSeenAckCounter: 1,
  };
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

const createReadySession = (savedParameters: SessionConnectionParameters) => {
  const [status, setStatus] = observable("created");
  const [signalStatus] = observable("encrypted");

  return {
    status,
    signalStatus,
    error: observable<string | undefined>(undefined)[0],
    peerInfo: observable(undefined)[0],
    getHandshakeParameters: () => ({
      version: 1,
      sessionId: savedParameters.sessionId,
      h: savedParameters.h,
      k: savedParameters.k,
      p: savedParameters.p,
      s: savedParameters.s,
    }),
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

    const savedParameters = await createSavedParameters();

    seededStorage.setSession(savedParameters);
    const restored = createReadySession(savedParameters);

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

    const savedParameters = await createSavedParameters();

    seededStorage.setSettings({ ...seededStorage.getSettings(), autoReconnect: false });
    seededStorage.setSession(savedParameters);

    const failed = createReadySession(savedParameters);

    failed._internal.isPairingInvalidated = true;
    failed.connect = async () => {
      throw new Error("No common transport with peer");
    };
    createSessionMock.mockResolvedValue(failed);

    const provider = createProvider({ storage: backingStorage });

    await expect(provider.restoreSession()).rejects.toThrow("No common transport with peer");
    expect(provider.storage.getSession()).toBeUndefined();
  });

  it("keeps a saved pairing when a transient resume failure does not invalidate it", async () => {
    const backingStorage = createStorage();
    const seededStorage = createProviderStorage({ storage: backingStorage });

    const savedParameters = await createSavedParameters();

    seededStorage.setSettings({ ...seededStorage.getSettings(), autoReconnect: false });
    seededStorage.setSession(savedParameters);

    const failed = createReadySession(savedParameters);

    failed.connect = async () => {
      throw new Error("Session resumption timed out");
    };
    createSessionMock.mockResolvedValue(failed);

    const provider = createProvider({ storage: backingStorage });

    await expect(provider.restoreSession()).rejects.toThrow("Session resumption timed out");
    expect(provider.storage.getSession()).toEqual(savedParameters);
  });

  it("clears a deterministically invalid saved session before retrying restore", async () => {
    const backingStorage = createStorage();
    const seededStorage = createProviderStorage({ storage: backingStorage });
    const savedParameters = await createSavedParameters();

    seededStorage.setSession(savedParameters);
    createSessionMock.mockRejectedValue(
      new InvalidSavedSessionError("Saved session key material is inconsistent"),
    );

    const provider = createProvider({ storage: backingStorage });

    await expect(provider.restoreSession()).rejects.toThrow(
      "Saved session key material is inconsistent",
    );
    expect(provider.storage.getSession()).toBeUndefined();
  });
});
