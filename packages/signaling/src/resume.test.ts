import { OPENLV_PROTOCOL_VERSION } from "@openlv/core";
import { generateKeyPair } from "@openlv/core/encryption";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { SignalMessage, SignalMessageResume, SignalMessageResumeAck, SignalMessageResumeConfirm } from "./messages.js";
import type { ResumeController, SignalingResumeState } from "./resume.js";
import { createResumeController } from "./resume.js";

const pairingId = "pairing";
const frame = (counter: number, publicKey: string): SignalMessageResume => ({
  type: "resume",
  payload: { version: OPENLV_PROTOCOL_VERSION, pairingId, publicKey, challenge: `challenge-${counter}`, counter },
  timestamp: 0,
});

const setup = async (options: { persist?: (state: SignalingResumeState) => void; send?: (message: unknown) => Promise<void>; initiate?: boolean; } = {}) => {
  const local = await generateKeyPair();
  const peer = await generateKeyPair();
  const saved: SignalingResumeState[] = [];
  const failures: Array<[string, boolean]> = [];
  const resumed: string[] = [];
  const controller = createResumeController({
    config: {
      pairingId,
      initiate: options.initiate ?? false,
      lastCounter: 4,
      lastSeenCounter: 2,
      lastSeenAckCounter: 2,
      persist: (state) => {
        saved.push(state);
        options.persist?.(state);
      },
    },
    publicKey: local.encryptionKey,
    expectedPeerKey: peer.encryptionKey,
    getPeerKey: () => undefined,
    acceptPeerKey: (key) => {
      resumed.push(key.toString());
    },
    onResumed: () => {
      resumed.push("resumed");
    },
    onFailure: (reason, invalidated) => {
      failures.push([reason, invalidated]);
    },
    send: options.send ?? (async () => {}),
  });

  return { controller, local, peer, saved, failures, resumed };
};

afterEach(() => vi.useRealTimers());

describe("authenticated signaling resume", () => {
  it("ignores duplicate and stale resume counters without invalidating pairing", async () => {
    const { controller, peer, saved, failures } = await setup();
    const fresh = frame(3, peer.encryptionKey.toString());

    await controller.handleResume(fresh);
    const afterFresh = saved.length;

    await controller.handleResume(fresh);
    await controller.handleResume(frame(2, peer.encryptionKey.toString()));
    await controller.handleResume({
      ...frame(2, "not-the-pinned-key"),
      payload: { ...frame(2, "not-the-pinned-key").payload, pairingId: "another-pairing" },
    });
    expect(saved).toHaveLength(afterFresh);
    expect(failures).toEqual([]);
  });

  it("ignores resume-ack frames with a mismatched pairing identity", async () => {
    const sent: SignalMessage[] = [];
    const { controller, saved, failures } = await setup({
      initiate: true,
      send: async (message) => {
        sent.push(message as SignalMessage);
      },
    });

    await controller.resume();
    await controller.handleResumeAck({
      type: "resume-ack",
      payload: {
        version: OPENLV_PROTOCOL_VERSION,
        pairingId: "another-pairing",
        publicKey: "not-the-pinned-key",
        challenge: "stale-challenge",
        initiatorChallenge: "wrong-challenge",
        counter: 3,
      },
      timestamp: 0,
    });

    expect(saved).toHaveLength(1);
    expect(sent).toHaveLength(1);
    expect(failures).toEqual([]);
    controller.teardown();
  });

  it("ignores advancing resumes with mismatched pairing identity or pinned key", async () => {
    const { controller, peer, failures, saved } = await setup();
    const wrongPeer = await generateKeyPair();

    await controller.handleResume({
      ...frame(3, peer.encryptionKey.toString()),
      payload: { ...frame(3, peer.encryptionKey.toString()).payload, pairingId: "another-pairing" },
    });
    await controller.handleResume(frame(3, wrongPeer.encryptionKey.toString()));
    expect(failures).toEqual([]);
    expect(saved).toEqual([]);

    await controller.handleResume(frame(3, peer.encryptionKey.toString()));
    expect(saved).toHaveLength(1);
    expect(failures).toEqual([]);
  });

  it("preserves a newer pending challenge when a stale resume is replayed", async () => {
    const sent: SignalMessage[] = [];
    const { controller, peer, saved, resumed } = await setup({
      send: async (message) => {
        sent.push(message as SignalMessage);
      },
    });

    await controller.handleResume(frame(6, peer.encryptionKey.toString()));
    await controller.handleResume(frame(5, peer.encryptionKey.toString()));

    const newerAck = sent.find(
      (message): message is SignalMessageResumeAck =>
        message.type === "resume-ack"
        && message.payload.initiatorChallenge === "challenge-6",
    );

    if (!newerAck) throw new Error("newer resume ack was not sent");

    await controller.handleResumeConfirm({
      type: "resume-confirm",
      payload: { pairingId, challenge: newerAck.payload.challenge },
      timestamp: 0,
    });

    expect(saved.at(-1)?.lastSeenCounter).toBe(6);
    expect(resumed).toContain("resumed");
  });

  it("does not let an unconfirmed high counter hide the genuine resume", async () => {
    const sent: SignalMessage[] = [];
    const { controller, peer, saved } = await setup({
      send: async (message) => {
        sent.push(message as SignalMessage);
      },
    });

    await controller.handleResume(frame(100, peer.encryptionKey.toString()));
    await controller.handleResume(frame(5, peer.encryptionKey.toString()));

    const acks = sent.filter(
      (message): message is SignalMessageResumeAck => message.type === "resume-ack",
    );

    expect(acks).toHaveLength(2);
    expect(acks.at(-1)?.payload.initiatorChallenge).toBe("challenge-5");

    await controller.handleResumeConfirm({
      type: "resume-confirm",
      payload: { pairingId, challenge: acks.at(-1)!.payload.challenge },
      timestamp: 0,
    });

    expect(saved.at(-1)?.lastSeenCounter).toBe(5);
  });

  it("does not publish an ack when advancing counter persistence fails", async () => {
    const send = vi.fn(async () => {});
    const { controller, peer, failures } = await setup({
      persist: () => {
        throw new Error("disk full");
      },
      send,
    });
    const handling = controller.handleResume(frame(3, peer.encryptionKey.toString()));

    await expect(handling).rejects.toThrow("disk full");
    expect(send).not.toHaveBeenCalled();
    expect(failures[0]?.[1]).toBe(false);
  });

  it("ignores a resume-confirm with a mismatched challenge without invalidating pairing", async () => {
    const { controller, peer, failures } = await setup();

    await controller.handleResume(frame(3, peer.encryptionKey.toString()));
    await controller.handleResumeConfirm({
      type: "resume-confirm",
      payload: { pairingId, challenge: "wrong-challenge" },
      timestamp: 0,
    });
    expect(failures).toEqual([]);
    controller.teardown();
  });

  it("does not persist an inbound counter before the sender proves the pinned key", async () => {
    const { controller, peer, saved } = await setup();

    await controller.handleResume(frame(Number.MAX_SAFE_INTEGER, peer.encryptionKey.toString()));
    expect(saved.at(-1)?.lastSeenCounter).toBe(2);
    controller.teardown();
  });

  it("ends an unauthenticated resume timeout without invalidating or advancing pairing state", async () => {
    vi.useFakeTimers();
    const { controller, peer, failures, saved } = await setup();

    await controller.handleResume(frame(Number.MAX_SAFE_INTEGER, peer.encryptionKey.toString()));
    await vi.advanceTimersByTimeAsync(45_000);
    expect(failures).toHaveLength(1);
    expect(failures[0]?.[1]).toBe(false);
    expect(saved.at(-1)?.lastSeenCounter).toBe(2);
  });

  it("keeps the inbound challenge obligation alive after completing its simultaneous outbound exchange", async () => {
    const sent: SignalMessage[] = [];
    const { controller, peer, failures, resumed, saved } = await setup({
      send: async (message) => {
        sent.push(message as SignalMessage);
      },
    });

    await controller.resume();
    const outgoing = sent.find((message): message is SignalMessageResume => message.type === "resume");

    if (!outgoing) throw new Error("resume frame was not sent");

    await controller.handleResume(frame(3, peer.encryptionKey.toString()));
    const ack = sent.find((message): message is SignalMessageResumeAck => message.type === "resume-ack");

    if (!ack) throw new Error("resume-ack frame was not sent");

    const ownAck: SignalMessageResumeAck = {
      type: "resume-ack",
      payload: { version: OPENLV_PROTOCOL_VERSION, pairingId, publicKey: peer.encryptionKey.toString(), challenge: "peer-challenge", initiatorChallenge: outgoing.payload.challenge, counter: 3 },
      timestamp: 0,
    };

    await controller.handleResumeAck(ownAck);
    expect(resumed).toContain("resumed");
    await controller.handleResumeConfirm({
      type: "resume-confirm",
      payload: { pairingId, challenge: ack.payload.challenge },
      timestamp: 0,
    } satisfies SignalMessageResumeConfirm);
    expect(failures).toEqual([]);
    expect(saved.at(-1)?.lastSeenCounter).toBe(3);
    expect(resumed.filter(value => value === peer.encryptionKey.toString())).toHaveLength(2);
    expect(resumed.filter(value => value === "resumed")).toHaveLength(1);
  });

  it("deduplicates an inbound confirmation while the outbound confirmation is still publishing", async () => {
    const sent: SignalMessage[] = [];
    let releaseConfirm!: () => void;
    let reportConfirm!: () => void;
    // eslint-disable-next-line unicorn/prefer-promise-with-resolvers -- Project libraries stop at ES2022.
    const confirmPending = new Promise<void>((resolve) => {
      releaseConfirm = resolve;
    });
    // eslint-disable-next-line unicorn/prefer-promise-with-resolvers -- Project libraries stop at ES2022.
    const confirmPublished = new Promise<void>((resolve) => {
      reportConfirm = resolve;
    });
    const { controller, peer, saved, resumed } = await setup({
      send: async (message) => {
        const sentMessage = message as SignalMessage;

        sent.push(sentMessage);

        if (sentMessage.type === "resume-confirm") {
          reportConfirm();
          await confirmPending;
        }
      },
    });

    try {
      await controller.resume();
      await controller.handleResume(frame(3, peer.encryptionKey.toString()));
      const outgoing = sent.find((message): message is SignalMessageResume => message.type === "resume");
      const inboundAck = sent.find((message): message is SignalMessageResumeAck => message.type === "resume-ack");

      if (!outgoing || !inboundAck) throw new Error("Resume frames were not sent");

      const completing = controller.handleResumeAck({
        type: "resume-ack",
        payload: {
          version: OPENLV_PROTOCOL_VERSION,
          pairingId,
          publicKey: peer.encryptionKey.toString(),
          challenge: "peer-challenge",
          initiatorChallenge: outgoing.payload.challenge,
          counter: 4,
        },
        timestamp: 0,
      });

      await confirmPublished;
      expect(saved.at(-1)?.lastSeenAckCounter).toBe(4);
      await controller.handleResumeConfirm({
        type: "resume-confirm",
        payload: { pairingId, challenge: inboundAck.payload.challenge },
        timestamp: 0,
      });
      expect(saved.at(-1)?.lastSeenCounter).toBe(3);
      expect(resumed.filter(value => value === "resumed")).toHaveLength(0);

      releaseConfirm();
      await completing;
      expect(resumed.filter(value => value === "resumed")).toHaveLength(1);
    }
    finally {
      releaseConfirm();
      controller.teardown();
    }
  });

  // A/B name the initiating peer's three-frame exchange, not the sender.
  // These are all orderings that preserve resume -> ack -> confirm per exchange.
  it.each([
    "AAABBB", "AABABB", "AABBAB", "AABBBA", "ABAABB",
    "ABABAB", "ABABBA", "ABBAAB", "ABBABA", "ABBBAA",
    "BAAABB", "BAABAB", "BAABBA", "BABAAB", "BABABA",
    "BABBAA", "BBAAAB", "BBAABA", "BBABAA", "BBBAAA",
  ])("notifies both peers once for simultaneous resumes and again after reload (%s)", async (deliveryOrder) => {
    const keys = await Promise.all([generateKeyPair(), generateKeyPair()]);
    const initialState = { pairingId, lastCounter: 0, lastSeenCounter: 0, lastSeenAckCounter: 0 };
    const persisted: [SignalingResumeState, SignalingResumeState] = [initialState, initialState];
    const resumed = [vi.fn(), vi.fn()] as const;
    const failures = [vi.fn(), vi.fn()] as const;

    type QueuedFrame = {
      recipient: 0 | 1;
      message: SignalMessageResume | SignalMessageResumeAck | SignalMessageResumeConfirm;
    };
    const exchanges: [QueuedFrame[], QueuedFrame[]] = [[], []];
    const createPeer = (index: 0 | 1): ResumeController => {
      const peerIndex = index === 0 ? 1 : 0;

      return createResumeController({
        config: {
          ...persisted[index],
          initiate: true,
          persist: (state) => {
            persisted[index] = state;
          },
        },
        publicKey: keys[index].encryptionKey,
        expectedPeerKey: keys[peerIndex].encryptionKey,
        getPeerKey: () => undefined,
        acceptPeerKey: vi.fn(),
        onResumed: resumed[index],
        onFailure: failures[index],
        send: async (message) => {
          const exchange = message.type === "resume-ack" ? peerIndex : index;

          exchanges[exchange].push({ recipient: peerIndex, message });
        },
      });
    };
    const controllers: [ResumeController, ResumeController] = [createPeer(0), createPeer(1)];
    const deliver = async (exchange: string) => {
      const queued = exchanges[exchange === "A" ? 0 : 1].shift();

      if (!queued) throw new Error(`No queued frame for exchange ${exchange}`);

      const receiver = controllers[queued.recipient];

      switch (queued.message.type) {
        case "resume": {
          await receiver.handleResume(queued.message);
          break;
        }
        case "resume-ack": {
          await receiver.handleResumeAck(queued.message);
          break;
        }
        case "resume-confirm": {
          await receiver.handleResumeConfirm(queued.message);
          break;
        }
      }
    };

    try {
      await Promise.all(controllers.map(controller => controller.resume()));
      const initialResume = exchanges[0][0]?.message;

      if (initialResume?.type !== "resume") throw new Error("Initial resume was not queued");

      for (const exchange of deliveryOrder) await deliver(exchange);

      expect(exchanges).toEqual([[], []]);
      expect(resumed[0]).toHaveBeenCalledTimes(1);
      expect(resumed[1]).toHaveBeenCalledTimes(1);
      expect(persisted[0].lastSeenCounter).toBe(1);
      expect(persisted[1].lastSeenCounter).toBe(1);

      // Reload only B: A remains live, and B must retain its replay high-water.
      controllers[1].teardown();
      controllers[1] = createPeer(1);
      await controllers[1].handleResume(initialResume);
      expect(exchanges).toEqual([[], []]);
      expect(resumed[1]).toHaveBeenCalledTimes(1);

      await controllers[1].resume();

      for (const exchange of "BBB") await deliver(exchange);

      expect(exchanges).toEqual([[], []]);
      expect(resumed[0]).toHaveBeenCalledTimes(2);
      expect(resumed[1]).toHaveBeenCalledTimes(2);
      expect(failures[0]).not.toHaveBeenCalled();
      expect(failures[1]).not.toHaveBeenCalled();
    }
    finally {
      controllers[0].teardown();
      controllers[1].teardown();
    }
  });

  it("signals every new inbound resume so a live peer renegotiates after repeated reloads", async () => {
    const sent: SignalMessage[] = [];
    const { controller, peer, resumed } = await setup({
      send: async (message) => {
        sent.push(message as SignalMessage);
      },
    });

    for (const counter of [3, 4]) {
      await controller.handleResume(frame(counter, peer.encryptionKey.toString()));
      let ack: SignalMessageResumeAck | undefined;

      for (const message of sent) {
        if (message.type === "resume-ack") ack = message;
      }

      if (!ack) throw new Error("resume acknowledgement was not sent");

      await controller.handleResumeConfirm({
        type: "resume-confirm",
        payload: { pairingId, challenge: ack.payload.challenge },
        timestamp: 0,
      });
    }

    expect(resumed.filter(value => value === "resumed")).toHaveLength(2);
    controller.teardown();
  });
});
