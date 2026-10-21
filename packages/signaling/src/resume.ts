import {
  isReplayCounter,
  OPENLV_PROTOCOL_VERSION,
  SESSION_SETUP_TIMEOUT_MS,
  type SessionResumeState,
} from "@openlv/core";
import type { EncryptionKey } from "@openlv/core/encryption";
import {
  generateUrlSafeRandomString,
  isSameEncryptionKey,
  parseEncryptionKey,
} from "@openlv/core/encryption";

import type {
  SignalMessageResume,
  SignalMessageResumeAck,
  SignalMessageResumeConfirm,
} from "./messages.js";
import { log } from "./utils/log.js";

const RESUME_CHALLENGE_LENGTH = 16;
const MAX_PENDING_RESPONDER_ATTEMPTS = 8;

type PendingResponder = {
  key: EncryptionKey;
  challenge: string;
  initiatorCounter: number;
  cancelTimeout: () => void;
};

/**
 * Outbound counters are persisted before publishing their frames. Inbound
 * replay counters are persisted only after the initiator proves possession of
 * the pinned key by returning the decrypted challenge.
 */
export type SignalingResumeState = SessionResumeState;

export type SignalingResumeConfig = SignalingResumeState & {
  // True when this peer should open the resume during setup; false when it
  // only needs to authenticate and accept an inbound resume.
  initiate: boolean;
  // Persist counter high-water updates before they complete the resume exchange.
  persist: (state: SignalingResumeState) => void;
};

export type ResumeController = {
  initiate: boolean;
  resume: () => Promise<void>;
  teardown: () => void;
  handleResume: (message: SignalMessageResume) => Promise<void>;
  handleResumeAck: (message: SignalMessageResumeAck) => Promise<void>;
  handleResumeConfirm: (message: SignalMessageResumeConfirm) => Promise<void>;
};

export type ResumeControllerHooks = {
  config: SignalingResumeConfig;
  publicKey: EncryptionKey;
  // Pinned peer key from persisted pairing state, if any.
  expectedPeerKey?: EncryptionKey;
  // The key currently known for the peer, used as a pin once the fresh
  // handshake has completed.
  getPeerKey: () => EncryptionKey | undefined;
  acceptPeerKey: (key: EncryptionKey) => void;
  onResumed: () => void;
  onFailure: (reason: string, isPairingInvalidated: boolean) => void;
  send: (
    message:
      | SignalMessageResume
      | SignalMessageResumeAck
      | SignalMessageResumeConfirm,
  ) => Promise<void>;
};

const isAdvancingCounter = (
  kind: "resume" | "resume-ack",
  counter: number,
  highWater: number,
): boolean => {
  if (isReplayCounter(counter) && counter > highWater) return true;

  log(`ignoring non-advancing ${kind} counter`, { counter, highWater });

  return false;
};

export const createResumeController = (
  hooks: ResumeControllerHooks,
): ResumeController => {
  const {
    config,
    publicKey,
    expectedPeerKey,
    getPeerKey,
    acceptPeerKey,
    onResumed,
    onFailure,
    send,
  } = hooks;
  let state: SignalingResumeState = {
    pairingId: config.pairingId,
    lastCounter: config.lastCounter,
    lastSeenCounter: config.lastSeenCounter,
    lastSeenAckCounter: config.lastSeenAckCounter,
  };
  let isStopped = false;
  let failureReason: string | undefined;
  let pendingInitiator:
    | {
      challenge: string;
      notified: boolean;
      cancelTimeout: () => void;
    }
    | undefined;
  const pendingResponders = new Map<number, PendingResponder>();

  const clearInitiator = () => {
    pendingInitiator?.cancelTimeout();
    pendingInitiator = undefined;
  };

  const clearResponders = () => {
    for (const responder of pendingResponders.values()) responder.cancelTimeout();

    pendingResponders.clear();
  };
  const teardown = () => {
    isStopped = true;
    clearInitiator();
    clearResponders();
  };

  const fail = (reason: string, isPairingInvalidated = false) => {
    if (isStopped) return;

    failureReason = isPairingInvalidated
      ? `${reason}; re-pair through a fresh openlv:// URI`
      : reason;
    teardown();
    onFailure(failureReason, isPairingInvalidated);
  };

  const persist = (next: SignalingResumeState): void => {
    try {
      config.persist(next);
    }
    catch (error) {
      fail(`Failed to persist resume state: ${error instanceof Error ? error.message : String(error)}`);

      throw new Error(failureReason, { cause: error });
    }

    if (isStopped) throw new Error(failureReason ?? "Resume controller has been torn down");

    state = next;
  };

  const nextCounter = (): number | undefined => {
    if (!isReplayCounter(state.lastCounter) || state.lastCounter === Number.MAX_SAFE_INTEGER) {
      fail("Resume counter cannot safely advance", true);

      return undefined;
    }

    return state.lastCounter + 1;
  };

  const parsePinnedKey = async (serialized: string): Promise<EncryptionKey | undefined> => {
    try {
      const key = await parseEncryptionKey(serialized);
      const pinned = expectedPeerKey ?? getPeerKey();

      return pinned !== undefined && isSameEncryptionKey(key, pinned) ? key : undefined;
    }
    catch {
      return undefined;
    }
  };

  const resume = async () => {
    if (isStopped) throw new Error(failureReason ?? "Resume controller has been torn down");

    if (pendingInitiator) return;

    const counter = nextCounter();

    if (counter === undefined) throw new Error(failureReason);

    persist({ ...state, lastCounter: counter });
    const challenge = generateUrlSafeRandomString(RESUME_CHALLENGE_LENGTH);

    const timer = setTimeout(() => fail("Authenticated resume timed out"), SESSION_SETUP_TIMEOUT_MS);

    pendingInitiator = {
      challenge,
      notified: false,
      cancelTimeout: () => clearTimeout(timer),
    };

    await send({
      type: "resume",
      payload: {
        version: OPENLV_PROTOCOL_VERSION,
        pairingId: state.pairingId,
        publicKey: publicKey.toString(),
        challenge,
        counter,
      },
      timestamp: Date.now(),
    });
  };

  const handleResume = async (message: SignalMessageResume) => {
    if (isStopped) return;

    const { payload } = message;

    if (!isAdvancingCounter("resume", payload.counter, state.lastSeenCounter)) return;

    if (payload.pairingId !== state.pairingId) return;

    const key = await parsePinnedKey(payload.publicKey);

    if (isStopped || !key) return;

    // Another concurrently delivered resume may have advanced the committed
    // counter while the pinned-key parser was awaiting.
    if (!isAdvancingCounter("resume", payload.counter, state.lastSeenCounter)) return;

    // Ignore duplicates without resetting a pending challenge or its timer.
    if (pendingResponders.has(payload.counter)) return;

    // Keep a bounded set so a replay cannot replace another in-flight proof.
    if (pendingResponders.size >= MAX_PENDING_RESPONDER_ATTEMPTS) return;

    const responderCounter = nextCounter();

    if (responderCounter === undefined) return;

    // Persist the responder's own outbound counter before publishing its ack.
    persist({ ...state, lastCounter: responderCounter });
    const responderChallenge = generateUrlSafeRandomString(RESUME_CHALLENGE_LENGTH);

    const timer = setTimeout(() => {
      pendingResponders.delete(payload.counter);

      if (pendingResponders.size === 0) {
        fail("Authenticated resume timed out awaiting challenge confirmation");
      }
    }, SESSION_SETUP_TIMEOUT_MS);

    pendingResponders.set(payload.counter, {
      key,
      challenge: responderChallenge,
      initiatorCounter: payload.counter,
      cancelTimeout: () => clearTimeout(timer),
    });

    await send({
      type: "resume-ack",
      payload: {
        version: OPENLV_PROTOCOL_VERSION,
        pairingId: state.pairingId,
        publicKey: publicKey.toString(),
        challenge: responderChallenge,
        initiatorChallenge: payload.challenge,
        counter: responderCounter,
      },
      timestamp: Date.now(),
    });
  };

  const handleResumeConfirm = async (message: SignalMessageResumeConfirm) => {
    if (isStopped) return;

    const { payload } = message;
    let responder: PendingResponder | undefined;

    for (const pending of pendingResponders.values()) {
      if (pending.challenge === payload.challenge) {
        responder = pending;
        break;
      }
    }

    if (!responder) return;

    if (payload.pairingId !== state.pairingId) return;

    persist({
      ...state,
      lastSeenCounter: Math.max(state.lastSeenCounter, responder.initiatorCounter),
    });
    clearResponders();
    acceptPeerKey(responder.key);

    // A simultaneous request preceded the peer's ack. Its proof still commits
    // the inbound replay counter, but the outbound exchange owns notification.
    if (!isStopped && responder.initiatorCounter > state.lastSeenAckCounter) {
      if (pendingInitiator) pendingInitiator.notified = true;

      onResumed();
    }
  };

  const handleResumeAck = async (message: SignalMessageResumeAck) => {
    if (isStopped) return;

    const { payload } = message;
    const initiator = pendingInitiator;

    if (!initiator) return;

    if (!isAdvancingCounter("resume-ack", payload.counter, state.lastSeenAckCounter)) return;

    if (payload.pairingId !== state.pairingId) return;

    if (payload.initiatorChallenge !== initiator.challenge) return;

    const key = await parsePinnedKey(payload.publicKey);

    if (isStopped || pendingInitiator !== initiator || !key) return;

    // A concurrent ack may have advanced the persisted high-water mark while
    // pinned-key parsing awaited; only the still-newer ack may proceed.
    if (!isAdvancingCounter("resume-ack", payload.counter, state.lastSeenAckCounter)) return;

    // An inbound confirm may arrive while send awaits. Commit first so it can
    // recognize a request that preceded this ack as the same simultaneous resume.
    persist({ ...state, lastSeenAckCounter: payload.counter });

    await send({
      type: "resume-confirm",
      payload: {
        pairingId: state.pairingId,
        challenge: payload.challenge,
      },
      timestamp: Date.now(),
    });

    if (isStopped || pendingInitiator !== initiator) return;

    clearInitiator();
    acceptPeerKey(key);

    if (!isStopped && !initiator.notified) onResumed();
  };

  return {
    initiate: config.initiate,
    resume,
    teardown,
    handleResume,
    handleResumeAck,
    handleResumeConfirm,
  };
};

