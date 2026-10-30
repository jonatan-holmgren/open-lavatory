import { describe, expect, it } from "vitest";

import { generateKeyPair } from "./asymmetric.js";
import { derivePeerChannels, type PeerChannelParameters } from "./peer.js";

const setup = async () => {
  const host = await generateKeyPair();
  const client = await generateKeyPair();
  const common = {
    version: 1,
    sessionId: "mytestsession111",
    hostPublicKey: host.encryptionKey.toString(),
    clientPublicKey: client.encryptionKey.toString(),
    psk: "12".repeat(16),
    hostNonce: "34".repeat(16),
    clientNonce: "56".repeat(16),
  };
  const hostParameters: PeerChannelParameters = { ...common, role: "host", localSecretKey: host.decryptionKey.toString() };
  const clientParameters: PeerChannelParameters = { ...common, role: "client", localSecretKey: client.decryptionKey.toString() };

  return { hostParameters, clientParameters };
};

describe("peer-bound channels", () => {
  it("authenticates directional signaling and transport independently", async () => {
    const { hostParameters, clientParameters } = await setup();
    const host = await derivePeerChannels(hostParameters);
    const client = await derivePeerChannels(clientParameters);
    const signal = await host.signaling.send.encrypt("hello", "header");

    await expect(client.transport.receive.decrypt(signal, "header")).rejects.toThrow();
    await expect(client.signaling.send.decrypt(signal, "header")).rejects.toThrow();
    await expect(client.signaling.receive.decrypt(signal, "wrong")).rejects.toThrow();
    await expect(client.signaling.receive.decrypt(signal, "header")).resolves.toBe("hello");
    await expect(client.signaling.receive.decrypt(signal, "header")).rejects.toThrow();
    const reply = await client.transport.send.encrypt("reply");

    await expect(host.transport.receive.decrypt(reply)).resolves.toBe("reply");
    expect(host.resumptionSecret).toBe(client.resumptionSecret);
    expect(host.resumptionSecret).toHaveLength(64);
  });

  it("binds keys to session and both fresh nonces", async () => {
    const { hostParameters, clientParameters } = await setup();
    const host = await derivePeerChannels(hostParameters);
    const ciphertext = await host.signaling.send.encrypt("message");

    for (const changed of [
      { sessionId: "othersession1111" },
      { hostNonce: "99".repeat(16) },
      { clientNonce: "99".repeat(16) },
      { psk: "ab".repeat(16) },
      { version: 2 },
    ]) {
      const client = await derivePeerChannels({ ...clientParameters, ...changed });

      await expect(client.signaling.receive.decrypt(ciphertext)).rejects.toThrow();
    }
  });

  it("rejects modified ciphertext, low-order keys and mismatched local keys", async () => {
    const { hostParameters, clientParameters } = await setup();
    const host = await derivePeerChannels(hostParameters);
    const client = await derivePeerChannels(clientParameters);
    const ciphertext = await host.signaling.send.encrypt("message");
    const bytes = Uint8Array.from(atob(ciphertext), char => char.codePointAt(0)!);

    bytes[bytes.length - 1] ^= 1;
    const modified = String.fromCodePoint(...bytes);
    const lowOrderKey = "\0".repeat(32);

    await expect(client.signaling.receive.decrypt(btoa(modified))).rejects.toThrow();
    await expect(derivePeerChannels({ ...hostParameters, clientPublicKey: btoa(lowOrderKey) })).rejects.toThrow();
    await expect(derivePeerChannels({ ...hostParameters, localSecretKey: clientParameters.localSecretKey })).rejects.toThrow();
    await expect(derivePeerChannels({ ...hostParameters, clientPublicKey: hostParameters.hostPublicKey })).rejects.toThrow();
  });

  it("keeps the resumption secret stable while deriving fresh attempt keys", async () => {
    const { hostParameters, clientParameters } = await setup();
    const initial = await derivePeerChannels(hostParameters);
    const resumedHost = await derivePeerChannels({ ...hostParameters, psk: initial.resumptionSecret, hostNonce: "78".repeat(16) });
    const resumedClient = await derivePeerChannels({ ...clientParameters, psk: initial.resumptionSecret, hostNonce: "78".repeat(16) });

    expect(resumedHost.resumptionSecret).toBe(initial.resumptionSecret);
    const ciphertext = await resumedHost.signaling.send.encrypt("resumed");

    await expect(resumedClient.signaling.receive.decrypt(ciphertext)).resolves.toBe("resumed");
    const oldClient = await derivePeerChannels(clientParameters);

    await expect(oldClient.signaling.receive.decrypt(ciphertext)).rejects.toThrow();
  });

  it("allows bounded reordering but rejects stale and concurrent replays", async () => {
    const { hostParameters, clientParameters } = await setup();
    const host = await derivePeerChannels(hostParameters);
    const client = await derivePeerChannels(clientParameters);
    const first = await host.transport.send.encrypt("first");
    const second = await host.transport.send.encrypt("second");

    await expect(client.transport.receive.decrypt(second)).resolves.toBe("second");
    const results = await Promise.allSettled([client.transport.receive.decrypt(first), client.transport.receive.decrypt(first)]);

    expect(results.filter(result => result.status === "fulfilled")).toHaveLength(1);
    const old = await host.transport.send.encrypt("old");
    let latest = "";

    for (let index = 0; index < 256; index++) latest = await host.transport.send.encrypt("later");
    await client.transport.receive.decrypt(latest);
    await expect(client.transport.receive.decrypt(old)).rejects.toThrow();
  });
});
