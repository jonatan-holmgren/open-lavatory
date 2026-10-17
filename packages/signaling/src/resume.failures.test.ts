import { describe, expect, it, vi } from "vitest";

import type { SignalingResumeState } from "./index.js";
import { Status } from "./index.js";
import {
  createAttackerPeers,
  createControlledChannel,
  createControlledPeers,
  createPeer,
  createSessionKeys,
  PAIRING_ID,
  readEncryptedFrame,
} from "./resume.fixtures.js";

describe("signaling resume failures", () => {
  it("times out a peer that cannot prove possession of the pinned private key", async () => {
    const { responder, attacker, responderChannel, attackerChannel } = await createAttackerPeers("pinned-key");

    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

    try {
      await attacker.layer.resume();
      await responderChannel.receive(attackerChannel.published[0]!);
      await attackerChannel.receive(responderChannel.published[0]!);

      expect(responder.layer.peerKey.get()).toBeUndefined();
      expect(attackerChannel.published).toHaveLength(1);

      await vi.advanceTimersByTimeAsync(45_000);

      expect(responder.layer.status.get()).toBe(Status.ERROR);
      expect(attacker.layer.status.get()).toBe(Status.ERROR);
      expect(responder.layer.peerKey.get()).toBeUndefined();
    }
    finally {
      await Promise.all([responder.layer.teardown(), attacker.layer.teardown()]);
      vi.useRealTimers();
    }
  });

  it("rejects a resume whose public key does not match the pin", async () => {
    const { responder, attacker, responderChannel, attackerChannel } = await createAttackerPeers("different-key");

    let isResumed = false;

    responder.layer.on("resume", () => {
      isResumed = true;
    });

    await attacker.layer.resume();
    await responderChannel.receive(attackerChannel.published[0]!);
    expect(responder.layer.status.get()).toBe(Status.ERROR);

    expect(isResumed).toBe(false);
    expect(responder.layer.peerKey.get()).toBeUndefined();

    await Promise.all([responder.layer.teardown(), attacker.layer.teardown()]);
  });

  it("fails on a mismatched pairing id and cannot reuse the pairing", async () => {
    const peers = await createControlledPeers();
    const { host, client, keys, hostChannel, clientChannel } = peers;
    const events: string[] = [];

    host.layer.on("error", (reason, isPairingInvalidated) => {
      expect(reason).toMatch(/pairing/i);
      expect(isPairingInvalidated).toBe(true);
      expect(host.layer.peerKey.get()).toBeUndefined();
      events.push("error");
    });
    host.layer.status.subscribe((status) => {
      if (status === Status.ERROR) events.push("status");
    });

    try {
      await client.layer.resume();
      await hostChannel.receive(clientChannel.published[0]!);
      await clientChannel.receive(hostChannel.published[0]!);
      await hostChannel.receive(clientChannel.published[1]!);

      expect(host.layer.status.get()).toBe(Status.ENCRYPTED);
      expect(host.layer.peerKey.get()).toBeDefined();

      const message = await readEncryptedFrame(clientChannel.published[0]!, keys.hostKeys.decryptionKey);

      if (message.type !== "resume") throw new Error("Expected resume");

      const mismatched = {
        ...message,
        payload: { ...message.payload, pairingId: "anotherpairing" },
      };

      await hostChannel.receive(`xh${await keys.hostKeys.encryptionKey.encrypt(JSON.stringify(mismatched))}`);
      await hostChannel.receive(clientChannel.published[0]!);

      expect(events).toEqual(["error", "status"]);
      expect(host.layer.status.get()).toBe(Status.ERROR);
      expect(hostChannel.published).toHaveLength(1);
      await expect(host.layer.resume()).rejects.toThrow(/failed/i);
      await expect(host.layer.setup()).rejects.toThrow(/failed/i);
      await expect(host.layer.send({ message: "blocked" })).rejects.toThrow(/failed/i);
    }
    finally {
      await Promise.all([host.layer.teardown(), client.layer.teardown()]);
    }
  });

  it("terminally rejects an acknowledgement with a mismatched challenge", async () => {
    const { host, client, keys, hostChannel, clientChannel } = await createControlledPeers();

    try {
      await client.layer.resume();
      await hostChannel.receive(clientChannel.published[0]!);

      const acknowledgement = await readEncryptedFrame(hostChannel.published[0]!, keys.clientKeys.decryptionKey);

      if (acknowledgement.type !== "resume-ack") throw new Error("Expected resume acknowledgement");

      const wrongChallenge = {
        ...acknowledgement,
        payload: { ...acknowledgement.payload, initiatorChallenge: "wrongchallenge" },
      };

      await clientChannel.receive(`xc${await keys.clientKeys.encryptionKey.encrypt(JSON.stringify(wrongChallenge))}`);
      await clientChannel.receive(hostChannel.published[0]!);

      expect(client.layer.status.get()).toBe(Status.ERROR);
      expect(client.layer.peerKey.get()).toBeUndefined();
      expect(clientChannel.published).toHaveLength(1);
      await expect(client.layer.resume()).rejects.toThrow(/failed/i);
    }
    finally {
      await Promise.all([host.layer.teardown(), client.layer.teardown()]);
    }
  });

  it("terminally rejects a mismatched proof even if a valid confirmation follows", async () => {
    const { host, client, keys, hostChannel, clientChannel } = await createControlledPeers();

    try {
      await client.layer.resume();
      await hostChannel.receive(clientChannel.published[0]!);
      await clientChannel.receive(hostChannel.published[0]!);

      const confirmation = await readEncryptedFrame(clientChannel.published[1]!, keys.hostKeys.decryptionKey);

      if (confirmation.type !== "resume-confirm") throw new Error("Expected resume confirmation");

      const wrongProof = {
        ...confirmation,
        payload: {
          ...confirmation.payload,
          proof: `${confirmation.payload.proof.startsWith("0") ? "1" : "0"}${confirmation.payload.proof.slice(1)}`,
        },
      };

      await hostChannel.receive(`xh${await keys.hostKeys.encryptionKey.encrypt(JSON.stringify(wrongProof))}`);
      await hostChannel.receive(clientChannel.published[1]!);

      expect(host.layer.status.get()).toBe(Status.ERROR);
      expect(host.layer.peerKey.get()).toBeUndefined();
      expect(hostChannel.published).toHaveLength(1);
      await expect(host.layer.send({ message: "blocked" })).rejects.toThrow(/failed/i);
    }
    finally {
      await Promise.all([host.layer.teardown(), client.layer.teardown()]);
    }
  });

  it("terminally times out an initiator after 45 seconds without an acknowledgement", async () => {
    const { host, client } = await createControlledPeers();
    const reasons: string[] = [];
    let isPairingInvalidated = false;

    client.layer.on("error", (reason, isInvalidated) => {
      reasons.push(reason);
      isPairingInvalidated = isInvalidated ?? false;
    });
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

    try {
      await client.layer.resume();
      await vi.advanceTimersByTimeAsync(44_999);
      expect(client.layer.status.get()).not.toBe(Status.ERROR);

      await vi.advanceTimersByTimeAsync(1);

      expect(client.layer.status.get()).toBe(Status.ERROR);
      expect(reasons).toHaveLength(1);
      expect(reasons[0]).toMatch(/timed out/i);
      expect(reasons[0]).toMatch(/pair/i);
      expect(isPairingInvalidated).toBe(true);
      await expect(client.layer.resume()).rejects.toThrow(/failed/i);
    }
    finally {
      await Promise.all([host.layer.teardown(), client.layer.teardown()]);
      vi.useRealTimers();
    }
  });

  it("completes a mutual resume once and safely ignores its late acknowledgement", async () => {
    const { host, client, hostChannel, clientChannel } = await createControlledPeers();
    let hostResumes = 0;
    let clientResumes = 0;

    host.layer.on("resume", () => hostResumes += 1);
    client.layer.on("resume", () => clientResumes += 1);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

    try {
      await Promise.all([host.layer.resume(), client.layer.resume()]);
      await vi.advanceTimersByTimeAsync(10_000);
      await hostChannel.receive(clientChannel.published[0]!);
      await clientChannel.receive(hostChannel.published[0]!);
      await hostChannel.receive(clientChannel.published[1]!);
      await clientChannel.receive(hostChannel.published[2]!);
      await clientChannel.receive(hostChannel.published[1]!);

      expect(host.layer.status.get()).toBe(Status.ENCRYPTED);
      expect(client.layer.status.get()).toBe(Status.ENCRYPTED);
      expect(hostResumes).toBe(1);
      expect(clientResumes).toBe(1);
      expect(clientChannel.published).toHaveLength(2);

      await vi.advanceTimersByTimeAsync(45_000);

      expect(host.layer.status.get()).toBe(Status.ENCRYPTED);
      expect(client.layer.status.get()).toBe(Status.ENCRYPTED);
      expect(hostResumes).toBe(1);
      expect(clientResumes).toBe(1);
    }
    finally {
      await Promise.all([host.layer.teardown(), client.layer.teardown()]);
      vi.useRealTimers();
    }
  });

  it.each(["initiator", "responder", "acknowledgement"] as const)(
    "fails closed when %s persistence throws",
    async (role) => {
      let clientWrites = 0;
      const { host, client, hostChannel, clientChannel } = await createControlledPeers({
        host: () => {
          if (role === "responder") throw new Error("storage unavailable");
        },
        client: () => {
          clientWrites += 1;

          if (role === "initiator" || (role === "acknowledgement" && clientWrites === 2)) {
            throw new Error("storage unavailable");
          }
        },
      });

      try {
        if (role === "initiator") {
          await expect(client.layer.resume()).rejects.toThrow(/persist/i);
          expect(clientChannel.published).toHaveLength(0);
          expect(client.layer.status.get()).toBe(Status.ERROR);
        }
        else {
          await client.layer.resume();
          await hostChannel.receive(clientChannel.published[0]!);

          if (role === "responder") {
            expect(hostChannel.published).toHaveLength(0);
            expect(host.layer.status.get()).toBe(Status.ERROR);
          }
          else {
            await clientChannel.receive(hostChannel.published[0]!);
            expect(clientChannel.published).toHaveLength(1);
            expect(client.layer.status.get()).toBe(Status.ERROR);
          }
        }
      }
      finally {
        await Promise.all([host.layer.teardown(), client.layer.teardown()]);
      }
    },
  );

  it("refuses to send a counter that cannot safely advance", async () => {
    const keys = await createSessionKeys();
    const channel = createControlledChannel();
    const client = await createPeer({
      channel: channel.channel,
      isHost: false,
      h: keys.h,
      encryptionKey: keys.clientKeys.encryptionKey,
      decryptionKey: keys.clientKeys.decryptionKey,
      pinnedKey: keys.hostKeys.encryptionKey,
      pairingId: PAIRING_ID,
      initiate: true,
      state: {
        pairingId: PAIRING_ID,
        lastCounter: Number.MAX_SAFE_INTEGER,
        lastSeenCounter: 0,
        lastSeenAckCounter: 0,
      },
    });

    try {
      await client.layer.setup();
      await expect(client.layer.resume()).rejects.toThrow(/counter/i);
      expect(client.layer.status.get()).toBe(Status.ERROR);
      expect(channel.published).toHaveLength(0);
    }
    finally {
      await client.layer.teardown();
    }
  });

  it("persists before publishing and clears both deadlines after simultaneous success", async () => {
    let hostState: SignalingResumeState | undefined;
    let clientState: SignalingResumeState | undefined;
    const hostSnapshots: (SignalingResumeState | undefined)[] = [];
    const clientSnapshots: (SignalingResumeState | undefined)[] = [];
    const { host, client, keys, hostChannel, clientChannel } = await createControlledPeers({
      host: state => hostState = { ...state },
      client: state => clientState = { ...state },
    });

    hostChannel.channel.publish = (payload) => {
      hostSnapshots.push(hostState);
      hostChannel.published.push(payload);
    };
    clientChannel.channel.publish = (payload) => {
      clientSnapshots.push(clientState);
      clientChannel.published.push(payload);
    };
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

    try {
      await Promise.all([host.layer.resume(), client.layer.resume()]);
      await hostChannel.receive(clientChannel.published[0]!);
      await clientChannel.receive(hostChannel.published[0]!);
      await hostChannel.receive(clientChannel.published[1]!);
      await clientChannel.receive(hostChannel.published[1]!);
      await hostChannel.receive(clientChannel.published[2]!);
      await clientChannel.receive(hostChannel.published[2]!);

      for (const [channel, key, snapshots] of [
        [hostChannel, keys.clientKeys.decryptionKey, hostSnapshots],
        [clientChannel, keys.hostKeys.decryptionKey, clientSnapshots],
      ] as const) {
        for (const [index, payload] of channel.published.entries()) {
          const message = await readEncryptedFrame(payload, key);

          if (message.type === "resume" || message.type === "resume-ack") {
            expect(snapshots[index]?.lastCounter).toBe(message.payload.counter);
          }
          else if (message.type === "resume-confirm") {
            expect(snapshots[index]?.lastSeenAckCounter).toBe(2);
          }
          else {
            throw new Error("Unexpected frame during resume");
          }
        }
      }

      expect(host.layer.status.get()).toBe(Status.ENCRYPTED);
      expect(client.layer.status.get()).toBe(Status.ENCRYPTED);
      await vi.advanceTimersByTimeAsync(45_000);
      expect(host.layer.status.get()).toBe(Status.ENCRYPTED);
      expect(client.layer.status.get()).toBe(Status.ENCRYPTED);
    }
    finally {
      await Promise.all([host.layer.teardown(), client.layer.teardown()]);
      vi.useRealTimers();
    }
  });

  it.each(["timeout", "teardown"] as const)(
    "does not publish or revive when %s interrupts async frame encryption",
    async (interruption) => {
      const keys = await createSessionKeys();
      const channel = createControlledChannel();
      let releaseEncryption!: () => void;
      let encryptionStarted!: () => void;
      const blocked = new Promise<void>(resolve => releaseEncryption = resolve);
      const started = new Promise<void>(resolve => encryptionStarted = resolve);
      const client = await createPeer({
        channel: channel.channel,
        isHost: false,
        h: keys.h,
        encryptionKey: keys.clientKeys.encryptionKey,
        decryptionKey: keys.clientKeys.decryptionKey,
        pinnedKey: {
          toString: keys.hostKeys.encryptionKey.toString,
          encrypt: async (message) => {
            encryptionStarted();
            await blocked;

            return await keys.hostKeys.encryptionKey.encrypt(message);
          },
        },
        pairingId: PAIRING_ID,
        initiate: true,
      });

      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

      try {
        await client.layer.setup();

        const sending = client.layer.resume();
        const rejected = expect(sending).rejects.toThrow(/failed|torn down/i);

        await started;

        if (interruption === "timeout") {
          await vi.advanceTimersByTimeAsync(45_000);
        }
        else {
          await client.layer.teardown();
        }

        releaseEncryption();
        await rejected;

        expect(channel.published).toHaveLength(0);
        expect(client.layer.peerKey.get()).toBeUndefined();
        expect(client.layer.status.get()).not.toBe(Status.ENCRYPTED);
        await vi.advanceTimersByTimeAsync(45_000);
        expect(client.layer.status.get()).toBe(
          interruption === "timeout" ? Status.ERROR : Status.HANDSHAKE_PARTIAL,
        );
      }
      finally {
        releaseEncryption();
        await client.layer.teardown();
        vi.useRealTimers();
      }
    },
  );
});
