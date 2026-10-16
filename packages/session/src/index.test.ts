import { decodeConnectionURL, encodeConnectionURL } from "@openlv/core";
import { generateSessionId } from "@openlv/core/encryption";
import { webrtc } from "@openlv/transport/webrtc";
import { describe, expect, test, vi } from "vitest";

import type * as DynamicModule from "./dynamic.js";
import { connectSession, createSession, type Session, SessionStatus } from "./index.js";

const { createChannel } = vi.hoisted(() => {
  const subscribersByTopic = new Map<string, Set<(payload: string) => void>>();

  const createChannel = (topic: string) => {
    const subscribers = subscribersByTopic.get(topic) ?? new Set<(payload: string) => void>();
    let subscriber: ((payload: string) => void) | undefined;

    subscribersByTopic.set(topic, subscribers);

    return {
      type: "memory",
      setup: () => {},
      teardown: () => {
        if (subscriber) subscribers.delete(subscriber);
      },
      publish: (payload: string) => {
        queueMicrotask(() => {
          for (const subscriber of subscribers) subscriber(payload);
        });
      },
      subscribe: (next: (payload: string) => void) => {
        subscriber = next;
        subscribers.add(next);
      },
    };
  };

  return { createChannel };
});

const createMemorySignaling = async ({ topic }: { topic: string; }) => {
  // Keep signaling loading within the mocked dynamic-loader boundary.
  const { createSignalingLayer } = await import("@openlv/signaling");

  return createSignalingLayer(createChannel(topic));
};

vi.mock("./dynamic.js", async (importOriginal) => {
  const actual = await importOriginal<typeof DynamicModule>();

  return {
    ...actual,
    loadSignaling: async () => createMemorySignaling,
  };
});

const createConnectedPair = async (sessionId: string) => {
  const sessionA = await createSession(
    { sessionId, p: "memory", s: "memory://relay" },
    [webrtc()],
    async () => ({ result: "host" }),
  );

  await sessionA.connect();

  const encodedUrl = encodeConnectionURL(sessionA.getHandshakeParameters());

  const sessionB = await connectSession(
    encodedUrl,
    async () => ({ result: "client" }),
    [webrtc()],
  );

  await sessionB.connect();
  await Promise.all([sessionA, sessionB].map(
    session => session.status.until(current => current === SessionStatus.CONNECTED),
  ));

  return { sessionA, sessionB };
};

describe("Session", () => {
  test("Should create and resume a session", async () => {
    const sessionA = await createSession(
      {
        sessionId: "mytestsession111",
        p: "memory",
        s: "memory://relay",
      },
      [webrtc()],
      async (message) => {
        console.log("sessionA received message", message);

        return { result: "success" };
      },
    );

    expect(sessionA).toBeDefined();
    console.log(sessionA.status.get());

    await sessionA.connect();

    const handshakeParametersA = sessionA.getHandshakeParameters();
    const encodedUrl = encodeConnectionURL(handshakeParametersA);

    console.log(encodedUrl);

    const decodedUrl = decodeConnectionURL(encodedUrl);

    expect(decodedUrl).toEqual(handshakeParametersA);

    //
    await new Promise(resolve => setTimeout(resolve, 1000));

    console.log("Connecting to session B");

    const sessionB = await connectSession(
      encodedUrl,
      async (message) => {
        console.log("sessionB received message", message);

        return { result: "success" };
      },
      [webrtc()],
    );

    console.log(sessionB.status.get());
    await sessionB.connect();

    await Promise.all([sessionA, sessionB].map(
      session => session.status.until(current => current === SessionStatus.CONNECTED),
    ));

    //
    console.log("A", sessionA.status.get());
    console.log("B", sessionB.status.get());

    const response = await sessionA.send({ data: "test" });

    console.log("response", response);

    expect(response).toEqual({ result: "success" });

    const savedA = sessionA.getConnectionParameters();
    const savedB = sessionB.getConnectionParameters();

    await Promise.all([sessionA.close(), sessionB.close()]);

    const resumedA = await createSession(savedA, [webrtc()], async () => ({ result: "host" }));
    const resumedB = await createSession(savedB, [webrtc()], async () => ({ result: "client" }));

    await resumedA.connect();
    await resumedB.connect();
    await Promise.all([resumedA, resumedB].map(
      session => session.status.until(current => current === SessionStatus.CONNECTED),
    ));

    await expect(resumedA.send({ method: "eth_chainId" })).resolves.toEqual({ result: "client" });
    await Promise.all([resumedA.close(), resumedB.close()]);
  });

  test("Stops after receiving close", async () => {
    const { sessionA, sessionB } = await createConnectedPair("peerclosetest001");

    await sessionB.close();
    await sessionA.status.until(current => current === SessionStatus.DISCONNECTED);

    await expect(sessionA.send({ method: "eth_chainId" }))
      .rejects.toThrow("Session not ready");
  });

  test("Keeps advertising until a peer joins and completes a fresh handshake", async () => {
    const host = await createSession(
      { p: "memory", s: "memory://relay" },
      [webrtc()],
      async () => ({ result: "host" }),
    );
    let client: Session | undefined;

    vi.useFakeTimers();

    try {
      await host.connect();
      await vi.advanceTimersByTimeAsync(60_000);

      expect(host.status.get()).toBe(SessionStatus.READY);
      expect(host.error.get()).toBeUndefined();
      vi.useRealTimers();

      client = await connectSession(
        encodeConnectionURL(host.getHandshakeParameters()),
        async () => ({ result: "client" }),
        [webrtc()],
      );

      await client.connect();
      await Promise.all([host, client].map(
        session => session.status.until(current => current === SessionStatus.CONNECTED),
      ));

      await expect(host.send({ method: "eth_chainId" })).resolves.toEqual({ result: "client" });
    }
    finally {
      await Promise.all([host.close(), client?.close()]);
      vi.useRealTimers();
    }
  });

  test("Should resume when only the host restarts", async () => {
    const { sessionA, sessionB } = await createConnectedPair("reloadhosttest01");
    const savedA = sessionA.getConnectionParameters();

    await Promise.all([
      sessionA._internal.signal.teardown(),
      sessionA._internal.transport?.teardown(),
    ]);

    const resumedA = await createSession(savedA, [webrtc()], async () => ({ result: "host" }));

    await resumedA.connect();
    await resumedA.status.until(current => current === SessionStatus.CONNECTED);

    await expect(resumedA.send({ method: "eth_chainId" })).resolves.toEqual({ result: "client" });
    await Promise.all([resumedA.close(), sessionB.close()]);
  });

  test("Should resume when only the client restarts", async () => {
    const { sessionA, sessionB } = await createConnectedPair("reloadclient0001");
    const savedB = sessionB.getConnectionParameters();

    await Promise.all([
      sessionB._internal.signal.teardown(),
      sessionB._internal.transport?.teardown(),
    ]);

    const resumedB = await createSession(savedB, [webrtc()], async () => ({ result: "client" }));

    await resumedB.connect();
    await resumedB.status.until(current => current === SessionStatus.CONNECTED);

    await expect(sessionA.send({ method: "eth_chainId" })).resolves.toEqual({ result: "client" });
    await Promise.all([sessionA.close(), resumedB.close()]);
  });

  test("Resumes the negotiated transport even when another transport is listed first", async () => {
    const preferred = { ...webrtc(), transportId: "preferred" };
    const shared = { ...webrtc(), transportId: "shared" };
    const host = await createSession(
      { p: "memory", s: "memory://relay" },
      [preferred, shared],
      async () => ({ result: "host" }),
    );

    await host.connect();

    const client = await connectSession(
      encodeConnectionURL(host.getHandshakeParameters()),
      async () => ({ result: "client" }),
      [shared],
    );

    await client.connect();
    await Promise.all([host, client].map(
      session => session.status.until(current => current === SessionStatus.CONNECTED),
    ));

    const savedHost = host.getConnectionParameters();
    const savedClient = client.getConnectionParameters();

    expect(savedHost.transportId).toBe("shared");
    expect(savedClient.transportId).toBe("shared");
    await Promise.all([host.close(), client.close()]);

    const resumedHost = await createSession(
      savedHost, [preferred, shared], async () => ({ result: "resumed-host" }),
    );
    const resumedClient = await createSession(
      savedClient, [preferred, shared], async () => ({ result: "resumed-client" }),
    );

    try {
      await Promise.all([resumedHost.connect(), resumedClient.connect()]);
      await Promise.all([resumedHost, resumedClient].map(
        session => session.status.until(current => current === SessionStatus.CONNECTED),
      ));

      expect(resumedHost.getConnectionParameters().transportId).toBe("shared");
      expect(resumedClient.getConnectionParameters().transportId).toBe("shared");
      await expect(resumedHost.send({ method: "eth_chainId" }))
        .resolves.toEqual({ result: "resumed-client" });
    }
    finally {
      await Promise.all([resumedHost.close(), resumedClient.close()]);
    }
  });

  test("Disconnects rather than resuming when the counter cannot be persisted", async () => {
    const { sessionA, sessionB } = await createConnectedPair(generateSessionId());
    const saved = sessionA.getConnectionParameters();

    await Promise.all([sessionA.close(), sessionB.close()]);
    const persistenceError = new Error("Storage is full");

    const resumed = await createSession(
      saved,
      [webrtc()],
      async () => ({ result: "host" }),
      {
        onConnectionParametersChange: () => {
          throw persistenceError;
        },
      },
    );

    try {
      await expect(resumed.connect()).rejects.toThrow();
      await resumed.status.until(current => current === SessionStatus.DISCONNECTED);

      expect(resumed.error.get()).toContain(persistenceError.message);
      // A failed write must not advance the counters reported locally.
      expect(resumed.getConnectionParameters()).toEqual(saved);
      await expect(resumed.send({ method: "eth_chainId" })).rejects.toThrow("Session not ready");
      await expect(resumed._internal.signal.resume()).rejects.toThrow();
    }
    finally {
      await resumed.close();
    }
  });

  test("Disconnects with a re-pairing error when the resumed peer never answers", async () => {
    const { sessionA, sessionB } = await createConnectedPair(generateSessionId());
    const saved = sessionA.getConnectionParameters();

    await Promise.all([sessionA.close(), sessionB.close()]);

    const resumed = await createSession(saved, [webrtc()], async () => ({ result: "host" }));

    vi.useFakeTimers();

    try {
      await resumed.connect();
      await vi.advanceTimersByTimeAsync(45_000);
      await resumed.status.until(current => current === SessionStatus.DISCONNECTED);

      expect(resumed.error.get()).toMatch(/timed out/i);
      expect(resumed.error.get()).toMatch(/pair/i);
      await expect(resumed._internal.signal.resume()).rejects.toThrow();
    }
    finally {
      await resumed.close();
      vi.useRealTimers();
    }
  });

  test("Answers a request even when its handler throws synchronously", async () => {
    const host = await createSession(
      { p: "memory", s: "memory://relay" },
      [webrtc()],
      async () => ({ result: "host" }),
    );

    await host.connect();

    const client = await connectSession(
      encodeConnectionURL(host.getHandshakeParameters()),
      () => { throw new Error("Handler failed"); },
      [webrtc()],
    );

    try {
      await client.connect();
      await Promise.all([host, client].map(
        session => session.status.until(current => current === SessionStatus.CONNECTED),
      ));

      await expect(host.send({ method: "eth_chainId" }))
        .resolves.toEqual({ error: { code: -32_603, message: "Internal error" } });
    }
    finally {
      await Promise.all([host.close(), client.close()]);
    }
  });
});
