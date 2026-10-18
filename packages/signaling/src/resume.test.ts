import { OPENLV_PROTOCOL_VERSION } from "@openlv/core";
import { generateKeyPair } from "@openlv/core/encryption";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { SignalMessage, SignalMessageResume, SignalMessageResumeAck, SignalMessageResumeConfirm } from "./messages.js";
import type { SignalingResumeState } from "./resume.js";
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

  it("ignores a resume-confirm with an invalid proof without invalidating pairing", async () => {
    const { controller, peer, failures } = await setup();

    await controller.handleResume(frame(3, peer.encryptionKey.toString()));
    await controller.handleResumeConfirm({ type: "resume-confirm", payload: { pairingId, proof: "0".repeat(64) }, timestamp: 0 });
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

  it("keeps the inbound proof obligation alive after completing its simultaneous outbound exchange", async () => {
    const sent: SignalMessage[] = [];
    const { controller, peer, local, failures, resumed, saved } = await setup({
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
    const proofInput = `${pairingId}|${peer.encryptionKey.toString()}|${local.encryptionKey.toString()}|challenge-3|${ack.payload.challenge}|3|6`;
    const proofBytes = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(proofInput),
    );
    const proof = Array.from(
      new Uint8Array(proofBytes),
      byte => byte.toString(16).padStart(2, "0"),
    ).join("");

    await controller.handleResumeConfirm({ type: "resume-confirm", payload: { pairingId, proof }, timestamp: 0 } satisfies SignalMessageResumeConfirm);
    expect(failures).toEqual([]);
    expect(saved.at(-1)?.lastSeenCounter).toBe(3);
    expect(resumed.filter(value => value === peer.encryptionKey.toString())).toHaveLength(2);
    expect(resumed.filter(value => value === "resumed")).toHaveLength(1);
  });
});
