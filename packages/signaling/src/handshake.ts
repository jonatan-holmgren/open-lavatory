import { type Observable, OPENLV_PROTOCOL_VERSION, type PeerCapabilities, type Setter } from "@openlv/core";
import {
  derivePeerChannels,
  deriveSymmetricKey,
  type EncryptionKey,
  isSameEncryptionKey,
  parseEncryptionKey,
  type PeerChannels,
  type SymmetricKey,
  validatePublicKeyHash,
} from "@openlv/core/encryption";
import type { EventEmitter } from "eventemitter3";

import type { SignalEventMap, SignalingHooks } from "./index.js";
import { parseSignalMessage, type SignalMessage } from "./messages.js";
import type { SignalingChannel } from "./protocol.js";
import { log } from "./utils/log.js";

type Channels = PeerChannels;

export const Status = {
  STANDBY: "standby", CONNECTING: "connecting", READY: "ready", HANDSHAKE: "handshake",
  HANDSHAKE_PARTIAL: "handshake-partial", ENCRYPTED: "encrypted", ERROR: "error",
} as const;
export type Status = (typeof Status)[keyof typeof Status];

export const XR_PREFIX = "x";
export const XR_H_PREFIX = "h";

/** Bootstrap frames use the invitation or saved pairing secret, never anonymous encryption. */
export const handshake = (isHost: boolean) => {
  const recipient = isHost ? "c" : "h";
  const localRecipient = isHost ? "h" : "c";

  return {
    async frame(key: SymmetricKey, message: SignalMessage): Promise<string> {
      const header = XR_H_PREFIX + recipient;

      return header + await key.encrypt(JSON.stringify(message), header);
    },
    async parse(key: SymmetricKey, frame: string): Promise<SignalMessage | undefined> {
      if (frame.slice(0, 2) !== XR_H_PREFIX + localRecipient) return undefined;

      return parseSignalMessage(await key.decrypt(frame.slice(2), frame.slice(0, 2)));
    },
  };
};

type Attempt = {
  clientNonce: string;
  hostNonce: string;
  psk: string;
  peer?: EncryptionKey;
  expectedPeer?: EncryptionKey;
  resumeKey?: SymmetricKey;
  earlyData?: object[];
  earlyBytes?: number;
  wakeNonce?: string;
  channels?: Channels;
  lastFrame: string;
};

const RETRY_MS = 2000;
const MAX_ATTEMPTS = 8;
const MAX_REPLIES = 64;
const MAX_EARLY_MESSAGES = 32;
const MAX_EARLY_BYTES = 256 * 1024;

const nonce = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, "0")).join("");
const message = <T extends SignalMessage["type"]>(type: T, payload: Extract<SignalMessage, { type: T; }>["payload"]): Extract<SignalMessage, { type: T; }> =>
  ({ type, payload, timestamp: Date.now() }) as Extract<SignalMessage, { type: T; }>;

/**
 * Own handshake attempts, authenticated channels and retransmissions. Relay
 * setup and teardown stay in the signaling layer.
 */
export const createHandshake = async (
  channel: SignalingChannel,
  hooks: SignalingHooks,
  state: {
    emitter: EventEmitter<SignalEventMap>;
    status: Observable<Status>;
    setStatus: Setter<Status>;
    setPeerKey: Setter<EncryptionKey | undefined>;
    setPeerCapabilities: Setter<PeerCapabilities | undefined>;
  },
) => {
  const { isHost, publicKey, capabilities } = hooks;
  const { emitter, status, setStatus, setPeerKey, setPeerCapabilities } = state;
  const codec = handshake(isHost);
  const recipient = isHost ? "c" : "h";
  const incomingHeader = XR_PREFIX + (isHost ? "h" : "c");
  const outgoingHeader = XR_PREFIX + recipient;
  let bootstrapSecret = hooks.resumptionSecret ?? hooks.k.toString();
  let bootstrapKey = hooks.resumptionSecret ? await deriveSymmetricKey(hooks.resumptionSecret) : hooks.k;
  let pin = hooks.expectedPeerKey;
  let active: Channels | undefined;
  let isStopped = false;
  let isCompleted = false;
  let clientAttempt: Attempt | undefined;
  const clientCandidates = new Map<string, Attempt>();
  const hostAttempts = new Map<string, Attempt>();
  const hostCandidates = new Map<string, Attempt>();
  // Only authenticated, successfully processed frames are cached. Re-publishing the
  // exact response allows retries without reusing an AEAD nonce or defeating replay checks.
  const replies = new Map<string, string>();
  const seenWakes = new Set<string>();
  let wakeFrame: string | undefined;
  let wakeNonce: string | undefined;
  let timer: ReturnType<typeof setInterval> | undefined;
  let receiveQueue = Promise.resolve();

  const remember = (frame: string, response: string) => {
    replies.set(frame, response);

    if (replies.size > MAX_REPLIES) replies.delete(replies.keys().next().value!);
  };
  const sendFrame = async (frame: string) => {
    if (!isStopped) await channel.publish(frame);
  };
  const bootstrapFrame = async (payload: SignalMessage) => await codec.frame(bootstrapKey, payload);
  const protectedFrame = async (channels: Channels, payload: SignalMessage) =>
    outgoingHeader + await channels.signaling.send.encrypt(JSON.stringify(payload), outgoingHeader);
  const derive = async (attempt: Attempt, peer: EncryptionKey) => await derivePeerChannels({
    sessionId: hooks.sessionId,
    version: OPENLV_PROTOCOL_VERSION,
    role: isHost ? "host" : "client",
    localSecretKey: hooks.secretKey,
    hostPublicKey: isHost ? publicKey.toString() : peer.toString(),
    clientPublicKey: isHost ? peer.toString() : publicKey.toString(),
    psk: attempt.psk,
    hostNonce: attempt.hostNonce,
    clientNonce: attempt.clientNonce,
  });
  const accept = async (attempt: Attempt, remoteCapabilities: PeerCapabilities) => {
    if (isStopped || !attempt.peer || !attempt.channels) return;

    if (pin && !isSameEncryptionKey(attempt.peer, pin)) return;

    const restart = isCompleted;

    pin = attempt.peer;
    active = attempt.channels;
    bootstrapSecret = active.resumptionSecret;
    bootstrapKey = await deriveSymmetricKey(bootstrapSecret);
    isCompleted = true;
    wakeFrame = undefined;
    wakeNonce = undefined;
    hostAttempts.clear();
    hostCandidates.clear();
    clientCandidates.clear();
    clientAttempt = undefined;
    setPeerKey(pin);
    setPeerCapabilities(remoteCapabilities);
    emitter.emit("handshake", { peerKey: pin, peerCapabilities: remoteCapabilities, transport: active.transport, resumptionSecret: bootstrapSecret }, restart);

    if (!isStopped) setStatus(Status.ENCRYPTED);

    const earlyData = attempt.earlyData ?? [];

    for (const item of earlyData) {
      if (!isStopped) emitter.emit("message", item);
    }
  };
  const start = async (requestedWake?: string) => {
    if (isStopped) throw new Error("Signaling has been torn down");

    if (isHost) {
      // Hosts wait for a fresh client flash. A saved host can wake a live client.
      if (!bootstrapSecret || (!pin && !isCompleted)) return;

      if (!wakeFrame) {
        wakeNonce = nonce();
        wakeFrame = await bootstrapFrame(message("flash", { nonce: wakeNonce, wake: true }));
      }

      await sendFrame(wakeFrame);

      return;
    }

    if (clientAttempt && (!requestedWake || !clientAttempt.wakeNonce || clientAttempt.wakeNonce === requestedWake)) return;

    const clientNonce = nonce();
    const frame = await bootstrapFrame(message("flash", { nonce: clientNonce, ...(requestedWake && { wakeNonce: requestedWake }) }));

    clientCandidates.clear();
    clientAttempt = { clientNonce, hostNonce: "", psk: bootstrapSecret, lastFrame: frame, wakeNonce: requestedWake };

    if (!isCompleted) setStatus(Status.HANDSHAKE);

    await sendFrame(frame);
  };
  const onBootstrap = async (frame: string, message_: SignalMessage, secret: string, key: SymmetricKey, expectedPeer?: EncryptionKey) => {
    if (message_.type === "flash") {
      if (!isHost) {
        if (!pin || !message_.payload.wake || seenWakes.has(message_.payload.nonce)) return;

        seenWakes.add(message_.payload.nonce);

        if (seenWakes.size > MAX_REPLIES) seenWakes.delete(seenWakes.values().next().value!);

        await start(message_.payload.nonce);

        return;
      }

      if (message_.payload.wake) return;

      if (message_.payload.wakeNonce && message_.payload.wakeNonce !== wakeNonce) return;

      const clientNonce = message_.payload.nonce;
      const existing = hostAttempts.get(clientNonce);

      if (existing) {
        if (existing.psk === secret) await sendFrame(existing.lastFrame);

        return;
      }

      const hostNonce = nonce();
      const response = await codec.frame(key, message("pubkey", { publicKey: publicKey.toString(), clientNonce, hostNonce }));

      hostAttempts.set(clientNonce, { clientNonce, hostNonce, psk: secret, expectedPeer, lastFrame: response });

      if (hostAttempts.size > MAX_ATTEMPTS) {
        const oldest = hostAttempts.keys().next().value!;
        const removed = hostAttempts.get(oldest)!;

        hostAttempts.delete(oldest);
        const removedFrames = new Set([removed.lastFrame]);

        for (const [key, candidate] of hostCandidates) {
          if (candidate.clientNonce !== oldest) {
            continue;
          }

          removedFrames.add(candidate.lastFrame);
          hostCandidates.delete(key);
        }

        for (const [key, value] of replies) {
          if (removedFrames.has(value)) replies.delete(key);
        }
      }

      if (!isCompleted) setStatus(Status.HANDSHAKE);

      remember(frame, response);
      await sendFrame(response);

      return;
    }

    if (message_.type !== "pubkey") return;

    const { clientNonce, hostNonce, publicKey: serializedPeer } = message_.payload;
    const attempt = isHost ? hostAttempts.get(clientNonce) : clientAttempt;

    if (!attempt || attempt.clientNonce !== clientNonce || attempt.psk !== secret || (isHost && attempt.hostNonce !== hostNonce)) return;

    let peer: EncryptionKey;

    try {
      peer = await parseEncryptionKey(serializedPeer);

      if (pin && !isSameEncryptionKey(peer, pin)) return;

      if (attempt.expectedPeer && !isSameEncryptionKey(peer, attempt.expectedPeer)) return;

      if (!isHost && !await validatePublicKeyHash(peer, hooks.h)) return;
    }
    catch { return; }

    let candidate: Attempt;

    if (isHost) {
      const key = `${clientNonce}:${peer.toString()}`;
      const previous = hostCandidates.get(key);

      if (previous) {
        remember(frame, previous.lastFrame);
        await sendFrame(previous.lastFrame);

        return;
      }

      if (hostCandidates.size >= 32) return;

      candidate = { ...attempt };
    }
    else {
      const previous = clientCandidates.get(hostNonce);

      if (previous) {
        remember(frame, previous.lastFrame);
        await sendFrame(previous.lastFrame);

        return;
      }

      // Never recreate an evicted candidate with the same key and counter.
      // Bound untrusted bootstrap input without evicting active candidates.
      if (clientCandidates.size >= 32) return;

      candidate = { ...attempt, hostNonce };
    }

    try {
      candidate.channels = await derive(candidate, peer);
    }
    catch { return; }

    if (isHost && candidate.channels.resumptionSecret !== bootstrapSecret) {
      candidate.resumeKey = await deriveSymmetricKey(candidate.channels.resumptionSecret);
    }

    candidate.peer = peer;

    if (isHost) {
      hostCandidates.set(`${clientNonce}:${peer.toString()}`, candidate);
    }
    else {
      clientCandidates.set(hostNonce, candidate);
    }

    const response = isHost
      ? await protectedFrame(candidate.channels, message("capabilities", capabilities))
      : await bootstrapFrame(message("pubkey", { publicKey: publicKey.toString(), clientNonce, hostNonce }));

    candidate.lastFrame = response;

    if (!isHost) attempt.lastFrame = response;

    if (!isCompleted) setStatus(Status.HANDSHAKE_PARTIAL);

    remember(frame, response);
    await sendFrame(response);
  };
  const onProtected = async (frame: string) => {
    // Snapshot the candidates because processing can clear the maps across awaits.
    // Iterator helpers are not available in all supported runtimes.
    // eslint-disable-next-line unicorn/prefer-iterator-to-array
    const attempts = isHost ? [...hostCandidates.values()] : [...clientCandidates.values()];

    for (const attempt of attempts) {
      if (!attempt.channels) continue;

      // Bound authenticated data retained while waiting for the client's final capabilities.
      if (isHost && frame.length > MAX_EARLY_BYTES) continue;

      let message_: SignalMessage | undefined;

      try {
        message_ = parseSignalMessage(await attempt.channels.signaling.receive.decrypt(frame.slice(2), incomingHeader));
      }
      catch { continue; }

      if (isHost && message_?.type === "data") {
        const early = attempt.earlyData ??= [];
        const bytes = attempt.earlyBytes ?? 0;

        if (early.length < MAX_EARLY_MESSAGES && bytes + frame.length <= MAX_EARLY_BYTES) {
          early.push(message_.payload);
          attempt.earlyBytes = bytes + frame.length;
        }

        return;
      }

      if (message_?.type !== "capabilities") return;

      if (isHost) {
        await accept(attempt, message_.payload);
      }
      else {
        const response = await protectedFrame(attempt.channels, message("capabilities", capabilities));

        remember(frame, response);
        // Retain the original final ciphertext for any duplicate confirmation.
        await accept(attempt, message_.payload);
        await sendFrame(response);
      }

      return;
    }

    if (!active) return;

    try {
      const message_ = parseSignalMessage(await active.signaling.receive.decrypt(frame.slice(2), incomingHeader));

      if (message_?.type === "data" && status.get() === Status.ENCRYPTED) emitter.emit("message", message_.payload);
    }
    catch { /* Malformed, unauthenticated, or replayed frames are ignored. */ }
  };
  const receive = async (frame: string) => {
    if (isStopped || typeof frame !== "string") return;

    const cached = replies.get(frame);

    if (cached) {
      await sendFrame(cached);

      return;
    }

    try {
      if (frame.startsWith(XR_H_PREFIX + (isHost ? "h" : "c"))) {
        let message_: SignalMessage | undefined;

        try {
          message_ = await codec.parse(bootstrapKey, frame);
        }
        catch { /* An invalid bootstrap frame may still use a candidate's resumption key. */ }

        if (message_) await onBootstrap(frame, message_, bootstrapSecret, bootstrapKey);
        else if (isHost) {
          // A client may have saved its peer-bound secret before its final packet
          // arrived. Only a candidate that derived that secret can authenticate it.
          for (const candidate of hostCandidates.values()) {
            if (!candidate.resumeKey || !candidate.channels || !candidate.peer) continue;

            let resumed: SignalMessage | undefined;

            try {
              resumed = await codec.parse(candidate.resumeKey, frame);
            }
            catch { /* Try the next candidate. */ }

            if (!resumed) continue;

            await onBootstrap(frame, resumed, candidate.channels.resumptionSecret, candidate.resumeKey, candidate.peer);
            break;
          }
        }
      }
      else if (frame.startsWith(incomingHeader)) await onProtected(frame);
    }
    catch (error) { log("Dropping malformed or unauthenticated signaling frame", error); }
  };

  return {
    get isStopped() { return isStopped; },
    start,
    receive(frame: string) {
      // Serialize receive so handshake and replay state cannot race.
      // eslint-disable-next-line unicorn/prefer-await
      receiveQueue = receiveQueue.then(() => receive(frame)).catch(error => log("Signaling receive failed", error));
    },
    startRetries() {
      timer = setInterval(() => {
        const frames = isHost
          ? [...hostAttempts.values(), ...hostCandidates.values()].map(attempt => attempt.lastFrame)
          : (clientAttempt ? [clientAttempt.lastFrame] : []);

        if (wakeFrame) frames.push(wakeFrame);

        for (const frame of frames) void sendFrame(frame).catch(error => log("Signaling retry failed", error));
      }, RETRY_MS);
    },
    stop() {
      isStopped = true;
      clearInterval(timer);
    },
    async send(payload: object) {
      if (isStopped || !active || status.get() !== Status.ENCRYPTED) throw new Error("Cannot send before peer confirmation");

      await sendFrame(await protectedFrame(active, message("data", payload)));
    },
  };
};
