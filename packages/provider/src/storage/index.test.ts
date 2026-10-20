import type { SerializedEncryptionKey, SessionConnectionParameters } from "@openlv/core";
import { generateKeyPair, hashPublicKey } from "@openlv/core/encryption";
import { describe, expect, it } from "vitest";

import { createProviderStorage } from "./index.js";

const SESSION_STORAGE_KEY = "@openlv/connector/session";

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

const createParameters = async (): Promise<SessionConnectionParameters> => {
  const local = await generateKeyPair();
  const peer = await generateKeyPair();

  return {
    version: 1,
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
    lastSeenCounter: 2,
    lastSeenAckCounter: 3,
  };
};

describe("saved session storage", () => {
  it("writes a versioned envelope and reads it back", async () => {
    const backing = createStorage();
    const storage = createProviderStorage({ storage: backing });
    const parameters = await createParameters();

    storage.setSession(parameters);

    const raw = JSON.parse(backing.getItem(SESSION_STORAGE_KEY)!) as {
      storageVersion: number;
      parameters: SessionConnectionParameters;
    };

    expect(raw.storageVersion).toBe(1);
    expect(raw.parameters).toEqual(parameters);
    expect(storage.getSession()).toEqual(parameters);
  });

  it("migrates legacy records that stored parameters directly", async () => {
    const backing = createStorage();
    const storage = createProviderStorage({ storage: backing });
    const parameters = await createParameters();

    backing.setItem(SESSION_STORAGE_KEY, JSON.stringify(parameters));

    expect(storage.getSession()).toEqual(parameters);
  });

  it("removes corrupt or unsupported records instead of returning them", async () => {
    const backing = createStorage();
    const storage = createProviderStorage({ storage: backing });

    backing.setItem(SESSION_STORAGE_KEY, "{");

    expect(storage.getSession()).toBeUndefined();
    expect(backing.getItem(SESSION_STORAGE_KEY)).toBeNull();
  });
});
