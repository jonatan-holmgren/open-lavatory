import { bytesToHex } from "@noble/ciphers/utils.js";
import { isReplayCounter, OPENLV_PROTOCOL_VERSION } from "@openlv/core";
import type { EncryptionKey } from "@openlv/core/encryption";
import { generateUrlSafeRandomString, parseEncryptionKey } from "@openlv/core/encryption";

import type {
  SignalMessageResume,
  SignalMessageResumeAck,
  SignalMessageResumeConfirm,
} from "./messages.js";
import { log } from "./utils/log.js";

const RESUME_CHALLENGE_LENGTH = 16;
const RESUME_TIMEOUT_MS = 45_000;

/**
 * Outbound counters are persisted before publishing their frames. Inbound
 * replay counters are persisted only after the initiator proves the pairing key.
 */
export type SignalingResumeState = {
  pairingId: string;
  lastCounter: number;
  lastSeenCounter: number;
  lastSeenAckCounter: number;
};

export type SignalingResumeConfig = SignalingResumeState & {
  // True when this peer should open the resume during setup; false when it
  // only needs to authenticate and accept an inbound resume.
  initiate: boolean;
  // Persist every high-water update before its corresponding frame is sent.
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

type ResumeTranscript = {
  pairingId: string;
  initiatorPublicKey: string;
  responderPublicKey: string;
  initiatorChallenge: string;
  responderChallenge: string;
  initiatorCounter: number;
  responderCounter: number;
};

const encoder = new TextEncoder();

/**
 * The proof binds the resume key to the whole transcript. Only a peer that has
 * decrypted the responder's fresh challenge can reconstruct it, which is how
 * the responder authenticates the initiator before accepting.
 */
const computeProof = async (transcript: ResumeTranscript): Promise<string> => {
  const parts = [
    transcript.pairingId,
    transcript.initiatorPublicKey,
    transcript.responderPublicKey,
    transcript.initiatorChallenge,
    transcript.responderChallenge,
    transcript.initiatorCounter.toString(),
    transcript.responderCounter.toString(),
  ];
  const encoded = encoder.encode(parts.join("|"));

  const digest = await crypto.subtle.digest("SHA-256", encoded);

  return bytesToHex(new Uint8Array(digest));
};

const isProofEqual = (a: string, b: string): boolean => {
  if (a.length !== b.length) return false;

  let difference = 0;

  for (let index = 0; index < a.length; index += 1) {
    difference |= (a.codePointAt(index) ?? 0) ^ (b.codePointAt(index) ?? 0);
  }

  return difference === 0;
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
  let didResume = false;
  let pendingInitiator:
    | {
      challenge: string;
      counter: number;
      cancelTimeout: () => void;
    }
    | undefined;
  let pendingResponder:
    | {
      key: EncryptionKey;
      transcript: ResumeTranscript;
      cancelTimeout: () => void;
    }
    | undefined;

  const clearInitiator = () => {
    pendingInitiator?.cancelTimeout();
    pendingInitiator = undefined;
  };

  const clearResponder = () => {
    pendingResponder?.cancelTimeout();
    pendingResponder = undefined;
  };
  const highestSeenResumeCounter = () => Math.max(
    state.lastSeenCounter,
    pendingResponder?.transcript.initiatorCounter ?? state.lastSeenCounter,
  );

  const teardown = () => {
    isStopped = true;
    clearInitiator();
    clearResponder();
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

      return pinned !== undefined && key.toString() === pinned.toString() ? key : undefined;
    }
    catch {
      return undefined;
    }
  };

  const complete = (key: EncryptionKey, role: "initiator" | "responder") => {
    if (isStopped) return;

    if (role === "initiator") clearInitiator();
    else clearResponder();

    acceptPeerKey(key);

    if (!isStopped && !didResume) {
      didResume = true;
      onResumed();
    }
  };

  const resume = async () => {
    if (isStopped) throw new Error(failureReason ?? "Resume controller has been torn down");

    if (pendingInitiator) return;

    const counter = nextCounter();

    if (counter === undefined) throw new Error(failureReason);

    persist({ ...state, lastCounter: counter });
    const challenge = generateUrlSafeRandomString(RESUME_CHALLENGE_LENGTH);

    const timer = setTimeout(() => fail("Authenticated resume timed out"), RESUME_TIMEOUT_MS);

    pendingInitiator = {
      challenge,
      counter,
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

    if (!isAdvancingCounter("resume", payload.counter, highestSeenResumeCounter())) return;

    if (payload.pairingId !== state.pairingId) return;

    const key = await parsePinnedKey(payload.publicKey);

    if (isStopped || !key) return;

    // Another concurrently delivered resume may have advanced this counter
    // while the pinned-key parser was awaiting.
    if (!isAdvancingCounter("resume", payload.counter, highestSeenResumeCounter())) return;

    const responderCounter = nextCounter();

    if (responderCounter === undefined) return;

    // Persist the responder's own outbound counter before publishing its ack.
    persist({ ...state, lastCounter: responderCounter });
    const responderChallenge = generateUrlSafeRandomString(RESUME_CHALLENGE_LENGTH);

    if (pendingResponder) log("resume replaced in-flight responder", state);

    clearResponder();
    const timer = setTimeout(() => fail("Authenticated resume timed out awaiting proof"), RESUME_TIMEOUT_MS);

    pendingResponder = {
      key,
      transcript: {
        pairingId: state.pairingId,
        initiatorPublicKey: payload.publicKey,
        responderPublicKey: publicKey.toString(),
        initiatorChallenge: payload.challenge,
        responderChallenge,
        initiatorCounter: payload.counter,
        responderCounter,
      },
      cancelTimeout: () => clearTimeout(timer),
    };

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
    const responder = pendingResponder;

    if (!responder) return;

    if (payload.pairingId !== state.pairingId) return;

    const expected = await computeProof(responder.transcript);

    if (isStopped || pendingResponder !== responder) return;

    if (!isProofEqual(expected, payload.proof)) return;

    // Only authenticated initiator counters become durable replay high-water marks.
    persist({
      ...state,
      lastSeenCounter: responder.transcript.initiatorCounter,
    });

    complete(responder.key, "responder");
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

    persist({ ...state, lastSeenAckCounter: payload.counter });

    const proof = await computeProof({
      pairingId: state.pairingId,
      initiatorPublicKey: publicKey.toString(),
      responderPublicKey: payload.publicKey,
      initiatorChallenge: initiator.challenge,
      responderChallenge: payload.challenge,
      initiatorCounter: initiator.counter,
      responderCounter: payload.counter,
    });

    if (isStopped || pendingInitiator !== initiator) return;

    await send({
      type: "resume-confirm",
      payload: {
        pairingId: state.pairingId,
        proof,
      },
      timestamp: Date.now(),
    });

    if (isStopped || pendingInitiator !== initiator) return;

    complete(key, "initiator");
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

