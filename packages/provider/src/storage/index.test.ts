import type { SessionConnectionParameters } from "@openlv/core";
import { describe, expect, test, vi } from "vitest";

import { createProviderStorage } from "./index.js";

const SESSION_STORAGE_KEY = "@openlv/connector/session";

const createMemoryStorage = (): Storage => {
  const map = new Map<string, string>();

  return {
    get length() {
      return map.size;
    },
    clear: () => {
      map.clear();
    },
    getItem: (key: string) => map.get(key) ?? null,
    key: (index: number) => Array.from(map.keys())[index] ?? null,
    removeItem: (key: string) => {
      map.delete(key);
    },
    setItem: (key: string, value: string) => {
      map.set(key, value);
    },
  };
};

const parameters: SessionConnectionParameters = {
  version: 1,
  sessionId: "abcdefghijklmnop",
  h: "0123456789abcdef",
  k: "0123456789abcdef0123456789abcdef",
  p: "ntfy",
  s: "https://ntfy.sh/",
  relyingPublicKey: "relying",
  encryptionKey: "public",
  decryptionKey: "private",
  pairingId: "pairingresume001",
  transportId: "wrtc",
  lastCounter: 1,
  lastSeenCounter: 2,
  lastSeenAckCounter: 3,
};

describe("provider session storage", () => {
  test("round-trips saved session parameters through the configured storage", () => {
    const memory = createMemoryStorage();
    const storage = createProviderStorage({ storage: memory });

    expect(storage.getSession()).toBeUndefined();

    storage.setSession(parameters);
    expect(storage.getSession()).toEqual(parameters);
    expect(createProviderStorage({ storage: memory }).getSession()).toEqual(parameters);

    storage.clearSession();
    expect(storage.getSession()).toBeUndefined();
  });

  test("persists sessions and counters in default localStorage without deleting settings", () => {
    const memory = createMemoryStorage();

    vi.stubGlobal("window", {});
    vi.stubGlobal("localStorage", memory);

    try {
      const first = createProviderStorage({});

      first.setSettings({ ...first.getSettings(), autoReconnect: true });
      first.setSession(parameters);

      const restored = createProviderStorage({});

      expect(restored.getSession()).toEqual(parameters);
      expect(restored.getSettings().autoReconnect).toBe(true);

      const advanced = { ...parameters, lastCounter: parameters.lastCounter + 1 };

      restored.setSession(advanced);
      expect(createProviderStorage({}).getSession()).toEqual(advanced);
      restored.clearSession();

      const cleared = createProviderStorage({});

      expect(cleared.getSession()).toBeUndefined();
      expect(cleared.getSettings().autoReconnect).toBe(true);
    }
    finally {
      vi.unstubAllGlobals();
    }
  });

  test("ignores malformed saved session parameters", () => {
    const memory = createMemoryStorage();
    const storage = createProviderStorage({ storage: memory });

    memory.setItem(SESSION_STORAGE_KEY, "{ not json");
    expect(storage.getSession()).toBeUndefined();

    memory.setItem(SESSION_STORAGE_KEY, JSON.stringify({ version: 1 }));
    expect(storage.getSession()).toBeUndefined();

    memory.setItem(
      SESSION_STORAGE_KEY,
      JSON.stringify({ ...parameters, decryptionKey: 42 }),
    );
    expect(storage.getSession()).toBeUndefined();

    // Invalid pairing state must not be restored.
    memory.setItem(
      SESSION_STORAGE_KEY,
      JSON.stringify({ ...parameters, pairingId: 42 }),
    );
    expect(storage.getSession()).toBeUndefined();
  });

  test.each([
    ["pairingId", ""],
    ["pairingId", "x".repeat(65)],
    ["transportId", ""],
    ["transportId", "x".repeat(33)],
    ["lastCounter", -1],
    ["lastCounter", Number.MAX_SAFE_INTEGER + 1],
    ["lastSeenCounter", 1.5],
    ["lastSeenAckCounter", "1"],
  ])("rejects an invalid persisted %s", (field, value) => {
    const memory = createMemoryStorage();
    const storage = createProviderStorage({ storage: memory });

    memory.setItem(SESSION_STORAGE_KEY, JSON.stringify({ ...parameters, [field]: value }));

    expect(storage.getSession()).toBeUndefined();
  });
});
