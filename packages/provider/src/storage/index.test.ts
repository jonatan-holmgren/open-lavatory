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

  it.each(["{", JSON.stringify({ storageVersion: 2, parameters: {} })])(
    "removes corrupt or unsupported record %s instead of returning it",
    (record) => {
      const backing = createStorage();
      const storage = createProviderStorage({ storage: backing });

      backing.setItem(SESSION_STORAGE_KEY, record);

      expect(storage.getSession()).toBeUndefined();
      expect(backing.getItem(SESSION_STORAGE_KEY)).toBeNull();
    },
  );
});
