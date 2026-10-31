import type { SerializedEncryptionKey, SessionConnectionParameters } from "@openlv/core";
import { generateKeyPair, hashPublicKey } from "@openlv/core/encryption";
import { describe, expect, it } from "vitest";

import { createProviderStorage } from "./index.js";
import { createStorage } from "./test-storage.js";

const SESSION_STORAGE_KEY = "@openlv/connector/session";

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
    resumptionSecret: "1".repeat(64),
    transportId: "wrtc",
  };
};

describe("saved session storage", () => {
  it("does not use the settings backend when sessionStorage is unavailable", async () => {
    const backing = createStorage();
    const storage = createProviderStorage({ storage: backing });
    const parameters = await createParameters();

    storage.setSession(parameters);

    expect(storage.getSession()).toEqual(parameters);
    expect(backing.getItem(SESSION_STORAGE_KEY)).toBeNull();
    expect(createProviderStorage({ storage: backing }).getSession()).toBeUndefined();
  });

  it("writes a versioned envelope and reads it back", async () => {
    const backing = createStorage();
    const storage = createProviderStorage({ sessionStorage: backing });
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

  it("discards old saved records that lack peer-bound credentials", async () => {
    const backing = createStorage();
    const storage = createProviderStorage({ sessionStorage: backing });
    const parameters = await createParameters();

    backing.setItem(SESSION_STORAGE_KEY, JSON.stringify({
      storageVersion: 1,
      parameters: {
        ...parameters,
        resumptionSecret: undefined,
        pairingId: "old-pairing",
        lastCounter: 1,
        lastSeenCounter: 1,
        lastSeenAckCounter: 1,
      },
    }));

    expect(storage.getSession()).toBeUndefined();
    expect(backing.getItem(SESSION_STORAGE_KEY)).toBeNull();
  });

  it.each(["{", JSON.stringify({ storageVersion: 2, parameters: {} })])(
    "removes corrupt or unsupported record %s instead of returning it",
    (record) => {
      const backing = createStorage();
      const storage = createProviderStorage({ sessionStorage: backing });

      backing.setItem(SESSION_STORAGE_KEY, record);

      expect(storage.getSession()).toBeUndefined();
      expect(backing.getItem(SESSION_STORAGE_KEY)).toBeNull();
    },
  );
});
