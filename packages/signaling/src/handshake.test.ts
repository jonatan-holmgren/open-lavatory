/* eslint-disable unicorn/consistent-boolean-name */
import { deriveSymmetricKey, generateKeyPair, hashPublicKey } from "@openlv/core/encryption";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createSignalingLayer, type SignalingHandshake, type SignalingLayer, Status } from "./index.js";
import type { SignalingChannel } from "./protocol.js";

const PSK = "00112233445566778899aabbccddeeff";
const layers: SignalingLayer[] = [];

afterEach(async () => {
  await Promise.all(layers.splice(0).map(layer => layer.teardown()));
});

const relay = () => {
  const listeners = new Set<(frame: string) => void>();
  const history: string[] = [];
  let drop: (frame: string) => boolean = () => false;

  return {
    history,
    setDrop(next: (frame: string) => boolean) { drop = next; },
    inject(frame: string) { for (const listener of listeners) listener(frame); },
    channel(): SignalingChannel {
      let handler: ((frame: string) => void) | undefined;

      return {
        type: "memory",
        setup() {},
        teardown() { if (handler) listeners.delete(handler); },
        // eslint-disable-next-line @stylistic/max-statements-per-line
        subscribe(next) { handler = next; listeners.add(next); },
        publish(frame) {
          history.push(frame);

          if (!drop(frame)) for (const listener of listeners) listener(frame);
        },
      };
    },
  };
};

const fixture = async () => {
  const bus = relay();
  const hostKey = await generateKeyPair();
  const clientKey = await generateKeyPair();
  const h = await hashPublicKey(hostKey.encryptionKey);
  const k = await deriveSymmetricKey(PSK);
  const hostEvents: SignalingHandshake[] = [];
  const clientEvents: SignalingHandshake[] = [];
  const create = async (isHost: boolean, saved?: string) => {
    const keys = isHost ? hostKey : clientKey;
    const layer = await createSignalingLayer(bus.channel())({
      isHost, h, k, sessionId: "session-id", secretKey: keys.decryptionKey.toString(),
      publicKey: keys.encryptionKey, capabilities: { transports: ["wrtc"] },
      ...(saved && { resumptionSecret: saved, expectedPeerKey: (isHost ? clientKey : hostKey).encryptionKey }),
    });

    layers.push(layer);
    layer.on("handshake", result => (isHost ? hostEvents : clientEvents).push(result));

    return layer;
  };
  const host = await create(true);
  const client = await create(false);

  return { bus, hostKey, clientKey, k, host, client, hostEvents, clientEvents, create };
};

const paired = async (host: SignalingLayer, client: SignalingLayer) => {
  await vi.waitFor(() => {
    expect(host.status.get()).toBe(Status.ENCRYPTED);
    expect(client.status.get()).toBe(Status.ENCRYPTED);
  });
};

describe("peer-bound signaling", () => {
  it("confirms both peers, separates transport keys and rejects replayed data", async () => {
    const f = await fixture();

    await f.host.setup();
    await f.client.setup();
    await paired(f.host, f.client);
    expect(f.hostEvents).toHaveLength(1);
    expect(f.clientEvents).toHaveLength(1);
    expect(f.hostEvents[0]!.resumptionSecret).toBe(f.clientEvents[0]!.resumptionSecret);
    const ciphertext = await f.hostEvents[0]!.transport.send.encrypt("private transport");

    await expect(f.clientEvents[0]!.transport.receive.decrypt(ciphertext)).resolves.toBe("private transport");
    await expect(f.clientEvents[0]!.transport.receive.decrypt(ciphertext)).rejects.toThrow();
    const received: object[] = [];

    f.client.on("message", value => received.push(value));
    await f.host.send({ hello: "peer" });
    await vi.waitFor(() => expect(received).toEqual([{ hello: "peer" }]));
    const data = f.bus.history.at(-1)!;

    f.bus.inject(data);
    await f.host.send({ hello: "again" });
    await vi.waitFor(() => expect(received).toEqual([{ hello: "peer" }, { hello: "again" }]));
  });

  it("does not accept a forged invitation-PSK host reply and recovers from it", async () => {
    const f = await fixture();
    let realHostReply = "";

    f.bus.setDrop((frame) => {
      if (frame.startsWith("hc") && !realHostReply) {
        realHostReply = frame;

        return true;
      }

      return false;
    });
    await f.host.setup();
    await f.client.setup();
    await vi.waitFor(() => expect(realHostReply).not.toBe(""));
    const real = JSON.parse(await f.k.decrypt(realHostReply.slice(2), "hc"));
    const forged = "hc" + await f.k.encrypt(JSON.stringify({
      type: "pubkey", timestamp: Date.now(),
      payload: { ...real.payload, hostNonce: "ff".repeat(16) },
    }), "hc");

    f.bus.inject(forged);
    await vi.waitFor(() => expect(f.client.status.get()).toBe(Status.HANDSHAKE_PARTIAL));
    expect(f.clientEvents).toHaveLength(0);
    expect(f.client.peerKey.get()).toBeUndefined();
    f.bus.inject(realHostReply);
    await paired(f.host, f.client);
    expect(f.clientEvents).toHaveLength(1);
  });

  it("retries identical confirmation ciphertext after packet loss", async () => {
    const f = await fixture();
    let lost = "";

    f.bus.setDrop((frame) => {
      if (frame.startsWith("xh") && !lost) {
        lost = frame;

        return true;
      }

      return false;
    });
    await f.host.setup();
    await f.client.setup();
    await vi.waitFor(() => expect(f.client.status.get()).toBe(Status.ENCRYPTED));
    expect(f.host.status.get()).not.toBe(Status.ENCRYPTED);
    await vi.waitFor(() => expect(f.host.status.get()).toBe(Status.ENCRYPTED), { timeout: 6000 });
    expect(f.bus.history.filter(frame => frame === lost).length).toBeGreaterThanOrEqual(2);
    expect(f.clientEvents).toHaveLength(1);
  });

  it("recovers if publishing the final confirmation initially fails", async () => {
    const f = await fixture();
    let isFailed = false;

    f.bus.setDrop((frame) => {
      if (frame.startsWith("xh") && !isFailed) {
        isFailed = true;
        throw new Error("relay unavailable");
      }

      return false;
    });
    await f.host.setup();
    await f.client.setup();
    await vi.waitFor(() => {
      expect(f.host.status.get()).toBe(Status.ENCRYPTED);
      expect(f.client.status.get()).toBe(Status.ENCRYPTED);
    }, { timeout: 6000 });
    expect(isFailed).toBe(true);
    expect(f.hostEvents).toHaveLength(1);
    expect(f.clientEvents).toHaveLength(1);
  }, 7000);

  it("delivers authenticated early data only after the final capabilities arrive", async () => {
    const f = await fixture();
    let final = "";

    f.bus.setDrop((frame) => {
      if (frame.startsWith("xh") && !final) final = frame;

      return frame === final;
    });
    const received: object[] = [];

    f.host.on("message", value => received.push(value));
    await f.host.setup();
    await f.client.setup();
    await vi.waitFor(() => expect(f.client.status.get()).toBe(Status.ENCRYPTED));
    expect(f.host.status.get()).not.toBe(Status.ENCRYPTED);
    await f.client.send({ early: true });
    const early = f.bus.history.at(-1)!;

    expect(received).toEqual([]);
    f.bus.inject(final);
    f.bus.inject(early);
    await vi.waitFor(() => expect(f.host.status.get()).toBe(Status.ENCRYPTED));
    await f.client.send({ barrier: true });
    await vi.waitFor(() => expect(received).toEqual([{ early: true }, { barrier: true }]));
  });

  it("resumes when the client restarts after its final capabilities are lost", async () => {
    const f = await fixture();
    let final = "";

    f.bus.setDrop((frame) => {
      if (frame.startsWith("xh") && !final) final = frame;

      return frame === final;
    });
    await f.host.setup();
    await f.client.setup();
    await vi.waitFor(() => expect(f.clientEvents).toHaveLength(1));
    expect(f.hostEvents).toHaveLength(0);
    const secret = f.clientEvents[0]!.resumptionSecret;

    await f.client.teardown();
    f.bus.setDrop(() => false);

    // Possessing the saved secret cannot substitute a different static client key.
    const saved = await deriveSymmetricKey(secret);
    const attacker = await generateKeyPair();
    const clientNonce = "aa".repeat(16);
    const before = f.bus.history.length;

    f.bus.inject("hh" + await saved.encrypt(JSON.stringify({
      type: "flash", payload: { nonce: clientNonce }, timestamp: Date.now(),
    }), "hh"));
    await vi.waitFor(() => expect(f.bus.history.slice(before).some(frame => frame.startsWith("hc"))).toBe(true));
    const reply = f.bus.history.slice(before).find(frame => frame.startsWith("hc"))!;
    const payload = JSON.parse(await saved.decrypt(reply.slice(2), "hc")).payload;

    f.bus.inject("hh" + await saved.encrypt(JSON.stringify({
      type: "pubkey", payload: { ...payload, publicKey: attacker.encryptionKey.toString() }, timestamp: Date.now(),
    }), "hh"));
    const client = await f.create(false, secret);

    await client.setup();
    await paired(f.host, client);
    expect(f.hostEvents).toHaveLength(1);
    expect(f.hostEvents[0]!.peerKey.toString()).toBe(f.clientKey.encryptionKey.toString());
    expect(f.hostEvents[0]!.resumptionSecret).toBe(secret);
    expect(f.clientEvents).toHaveLength(2);
  });

  it("does not complete a handshake from an old wake after a client restart", async () => {
    const f = await fixture();

    await f.host.setup();
    await f.client.setup();
    await paired(f.host, f.client);
    const secret = f.hostEvents[0]!.resumptionSecret;

    await f.host.teardown();
    let host = await f.create(true, secret);
    const beforeWake = f.bus.history.length;

    await host.setup();
    await vi.waitFor(() => expect(f.hostEvents).toHaveLength(2));
    const wake = f.bus.history.slice(beforeWake).find(frame => frame.startsWith("hc"))!;

    await f.client.teardown();
    const client = await f.create(false, secret);

    await client.setup();
    await vi.waitFor(() => expect(f.clientEvents).toHaveLength(3));
    await vi.waitFor(() => expect(f.hostEvents).toHaveLength(3));
    const beforeReplay = f.bus.history.length;

    f.bus.inject(wake);
    await vi.waitFor(() => expect(f.bus.history.slice(beforeReplay).some(frame => frame.startsWith("hh"))).toBe(true));
    const received: object[] = [];

    host.on("message", value => received.push(value));
    await client.send({ barrier: true });
    await vi.waitFor(() => expect(received).toEqual([{ barrier: true }]));
    expect(f.bus.history.slice(beforeReplay).some(frame => frame.startsWith("hc"))).toBe(false);
    expect(f.hostEvents).toHaveLength(3);
    expect(f.clientEvents).toHaveLength(3);

    // A new host wake must replace the unanswered stale-wake attempt.
    await host.teardown();
    host = await f.create(true, secret);
    await host.setup();
    await vi.waitFor(() => expect(f.hostEvents).toHaveLength(4));
    await vi.waitFor(() => expect(f.clientEvents).toHaveLength(4));
    await paired(host, client);
  });

  it("reuses the same confirmation for equivalent re-encrypted pubkey packets", async () => {
    const f = await fixture();

    f.bus.setDrop(frame => frame.startsWith("hc") || frame.startsWith("xc"));
    await f.host.setup();
    await f.client.setup();
    await vi.waitFor(() => expect(f.bus.history.some(frame => frame.startsWith("hc"))).toBe(true));
    const hostReply = f.bus.history.find(frame => frame.startsWith("hc"))!;
    const hostPayload = JSON.parse(await f.k.decrypt(hostReply.slice(2), "hc")).payload;
    const body = { ...hostPayload, publicKey: f.clientKey.encryptionKey.toString() };
    const first = "hh" + await f.k.encrypt(JSON.stringify({ type: "pubkey", payload: body, timestamp: 1 }), "hh");
    const second = "hh" + await f.k.encrypt(JSON.stringify({ type: "pubkey", payload: body, timestamp: 2 }), "hh");

    f.bus.inject(first);
    await vi.waitFor(() => expect(f.bus.history.filter(frame => frame.startsWith("xc"))).toHaveLength(1));
    f.bus.inject(second);
    await vi.waitFor(() => expect(f.bus.history.filter(frame => frame.startsWith("xc"))).toHaveLength(2));
    const confirmations = f.bus.history.filter(frame => frame.startsWith("xc"));

    expect(confirmations[0]).toBe(confirmations[1]);
    expect(f.hostEvents).toHaveLength(0);
  });

  it("ignores late invitation holders once the peer is pinned", async () => {
    const f = await fixture();

    await f.host.setup();
    await f.client.setup();
    await paired(f.host, f.client);
    const forged = "hh" + await f.k.encrypt(JSON.stringify({
      type: "flash", payload: { nonce: "aa".repeat(16) }, timestamp: Date.now(),
    }), "hh");
    const received: object[] = [];

    f.host.on("message", value => received.push(value));
    f.bus.inject(forged);
    await f.client.send({ barrier: true });
    await vi.waitFor(() => expect(received).toEqual([{ barrier: true }]));
    expect(f.hostEvents).toHaveLength(1);
    expect(f.host.peerKey.get()?.toString()).toBe(f.clientKey.encryptionKey.toString());
  });

  it("rejects a different client key even with the saved bootstrap secret", async () => {
    const f = await fixture();

    await f.host.setup();
    await f.client.setup();
    await paired(f.host, f.client);
    const saved = await deriveSymmetricKey(f.hostEvents[0]!.resumptionSecret);
    const attacker = await generateKeyPair();
    const clientNonce = "aa".repeat(16);
    const before = f.bus.history.length;

    f.bus.inject("hh" + await saved.encrypt(JSON.stringify({
      type: "flash", payload: { nonce: clientNonce }, timestamp: Date.now(),
    }), "hh"));
    await vi.waitFor(() => expect(f.bus.history.slice(before).some(frame => frame.startsWith("hc"))).toBe(true));
    const reply = f.bus.history.slice(before).find(frame => frame.startsWith("hc"))!;
    const payload = JSON.parse(await saved.decrypt(reply.slice(2), "hc")).payload;
    const forged = "hh" + await saved.encrypt(JSON.stringify({
      type: "pubkey", payload: { ...payload, publicKey: attacker.encryptionKey.toString() }, timestamp: Date.now(),
    }), "hh");
    const received: object[] = [];

    f.host.on("message", value => received.push(value));
    f.bus.inject(forged);
    await f.client.send({ barrier: true });
    await vi.waitFor(() => expect(received).toEqual([{ barrier: true }]));
    expect(f.hostEvents).toHaveLength(1);
    expect(f.host.peerKey.get()?.toString()).toBe(f.clientKey.encryptionKey.toString());
  });

  it.each(["host", "client", "both"] as const)("reconnects after %s reload with pinned peers", async (who) => {
    const f = await fixture();

    await f.host.setup();
    await f.client.setup();
    await paired(f.host, f.client);
    const secret = f.hostEvents[0]!.resumptionSecret;
    let { host, client } = f;

    if (who !== "client") { await host.teardown(); host = await f.create(true, secret); }

    if (who !== "host") { await client.teardown(); client = await f.create(false, secret); }

    if (who !== "client") await host.setup();

    if (who !== "host") await client.setup();

    await vi.waitFor(() => {
      expect(f.hostEvents).toHaveLength(2);
      expect(f.clientEvents).toHaveLength(2);
    }, { timeout: 6000 });
    await paired(host, client);
    expect(f.hostEvents[1]!.resumptionSecret).toBe(secret);
    expect(f.clientEvents[1]!.resumptionSecret).toBe(secret);
    const data = await f.hostEvents[1]!.transport.send.encrypt("new connection");

    await expect(f.clientEvents[1]!.transport.receive.decrypt(data)).resolves.toBe("new connection");
  });
});
