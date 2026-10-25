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
import { createStorage } from "./storage/test-storage.js";

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
    send: async (message: { id: number; method: string; }) => ({
      jsonrpc: "2.0",
      id: message.id,
      result: message.method === "eth_accounts" ? [] : "0x1",
    }),
    emitter: new EventEmitter(),
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

    expect(provider.session.get()).toBe(restored);
    expect(await provider.getAccounts()).toEqual([]);
  });

  it("clears a saved pairing when terminal closure invalidates it", async () => {
    const backingStorage = createStorage();
    const seededStorage = createProviderStorage({ storage: backingStorage });

    const savedParameters = await createSavedParameters();

    seededStorage.setSettings({ ...seededStorage.getSettings(), autoReconnect: false });
    seededStorage.setSession(savedParameters);

    const failed = createReadySession(savedParameters);

    failed.connect = async () => {
      failed.emitter.emit("close", "Resume counter cannot safely advance", true);
      throw new Error("Resume counter cannot safely advance");
    };
    createSessionMock.mockResolvedValue(failed);

    const provider = createProvider({ storage: backingStorage });

    await expect(provider.restoreSession()).rejects.toThrow("Resume counter cannot safely advance");
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
