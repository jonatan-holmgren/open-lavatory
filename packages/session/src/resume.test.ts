import type { SessionConnectionParameters } from "@openlv/core";
import { generateHandshakeKey, generateKeyPair, generateSessionId, hashPublicKey } from "@openlv/core/encryption";
import { createSignalingLayer } from "@openlv/signaling";
import { webrtc } from "@openlv/transport/webrtc";
import { beforeAll, describe, expect, test, vi } from "vitest";

import type * as DynamicModule from "./dynamic.js";
import { createSession, type Session, SessionStatus } from "./index.js";

const control: { stage: "setup" | "subscribe"; stalled?: Promise<void>; } = { stage: "setup" };
const createStalledSignaling = () => createSignalingLayer({
  type: "memory",
  setup: () => (control.stage === "setup" ? control.stalled : undefined),
  subscribe: () => (control.stage === "subscribe" ? control.stalled : undefined),
  publish: () => {},
  teardown: () => {},
});

vi.mock("./dynamic.js", async (importOriginal) => {
  const actual = await importOriginal<typeof DynamicModule>();

  return {
    ...actual,
    loadSignaling: async () => createStalledSignaling,
  };
});

describe("Session resumption", () => {
  let saved: SessionConnectionParameters;

  beforeAll(async () => {
    const [local, peer, handshakeKey] = await Promise.all([
      generateKeyPair(), generateKeyPair(), generateHandshakeKey(),
    ]);
    const sessionId = generateSessionId();

    saved = {
      version: 1,
      sessionId,
      h: await hashPublicKey(local.encryptionKey),
      k: handshakeKey.toString(),
      p: "memory",
      s: "memory://relay",
      encryptionKey: local.encryptionKey.toString(),
      decryptionKey: local.decryptionKey.toString(),
      relyingPublicKey: peer.encryptionKey.toString(),
      pairingId: sessionId,
      transportId: "wrtc",
      lastCounter: 0,
      lastSeenCounter: 0,
      lastSeenAckCounter: 0,
    };
  });

  test("Rejects a negative saved counter", async () => {
    await expect(createSession({ ...saved, lastCounter: -1 }, [webrtc()], async () => ({})))
      .rejects.toThrow();
  });

  test("Rejects incomplete saved state rather than starting a fresh pairing", async () => {
    await expect(createSession({
      p: saved.p,
      s: saved.s,
      encryptionKey: saved.encryptionKey,
    } as SessionConnectionParameters, [webrtc()], async () => ({})))
      .rejects.toThrow();
  });

  test.each(["setup", "subscribe"] as const)("Includes stalled signaling %s in the resume deadline", async (stage) => {
    control.stage = stage;
    let release!: () => void;

    // eslint-disable-next-line unicorn/prefer-promise-with-resolvers -- Project libraries stop at ES2022.
    control.stalled = new Promise<void>((resolve) => {
      release = resolve;
    });
    const resumed: Session = await createSession(saved, [webrtc()], async () => ({}));

    expect(resumed.getConnectionParameters()).toEqual(saved);
    vi.useFakeTimers();

    try {
      const rejected = expect(resumed.connect()).rejects.toThrow();

      await vi.advanceTimersByTimeAsync(44_999);
      expect(resumed.status.get()).toBe(SessionStatus.SIGNALING);
      expect(resumed.error.get()).toBeUndefined();
      await vi.advanceTimersByTimeAsync(1);
      await rejected;

      expect(resumed.status.get()).toBe(SessionStatus.DISCONNECTED);
      expect(resumed.error.get()).toEqual(expect.any(String));
      release();
      await vi.advanceTimersByTimeAsync(0);
      expect(resumed.status.get()).toBe(SessionStatus.DISCONNECTED);
      await expect(resumed.connect()).rejects.toThrow();
      await expect(resumed.send({ method: "eth_chainId" })).rejects.toThrow();
    }
    finally {
      release();
      await resumed.close();
      vi.useRealTimers();
    }
  });
});
