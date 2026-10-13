import type { Observable } from "@openlv/core";
import { make, observable } from "@openlv/core";
import type { EncryptionKey, SymmetricKey } from "@openlv/core/encryption";
import { parseEncryptionKey, validatePublicKeyHash } from "@openlv/core/encryption";
import { EventEmitter } from "eventemitter3";
import { match } from "ts-pattern";

import type { SignalingStage } from "./handshake.js";
import { handshake, XR_H_PREFIX, XR_PREFIX } from "./handshake.js";
import type { PeerCapabilities, SignalMessage } from "./messages.js";
import type { SignalingChannel } from "./protocol.js";
import type { SignalingResumeConfig } from "./resume.js";
import { createResumeController } from "./resume.js";
import { log } from "./utils/log.js";

export * from "./messages.js";
export * from "./protocol.js";
export type { SignalingResumeConfig, SignalingResumeState } from "./resume.js";

export const Status = {
  STANDBY: "standby",
  CONNECTING: "connecting",
  READY: "ready",
  HANDSHAKE: "handshake",
  HANDSHAKE_PARTIAL: "handshake-partial",
  ENCRYPTED: "encrypted",
  ERROR: "error",
} as const;
export type Status = (typeof Status)[keyof typeof Status];

export type SignalEventMap = {
  message: (message: object) => void;
  error: (reason: string) => void;
  // Emitted once an inbound or outbound resume has completed, so consumers
  // can tear down and renegotiate the transport.
  resume: () => void;
  // Emitted when a restarting peer re-runs the fresh handshake against us, so
  // consumers can tear down the old transport before the new one is built.
  restart: () => void;
};

export type SignalingHooks = {
  isHost: boolean;
  h: string;
  k: SymmetricKey;
  // Our capabilities, advertised to the peer during the handshake
  capabilities: PeerCapabilities;
  // Decrypt using our private key
  decrypt: (message: string) => Promise<string>;
  // Encrypt to relying party
  encrypt: (message: string) => Promise<string>;
  // our public key
  publicKey: EncryptionKey;
  // Persisted peer key to authenticate a resumed session.
  expectedPeerKey?: EncryptionKey;
  // Durable pairing identity. When present the layer can resume the pairing;
  // `initiate` also skips the fresh handshake.
  resume?: SignalingResumeConfig;
  canEncrypt: () => boolean;
};

export type SignalingContext = {
  type: string;

  // Sending only works once keys are exchanged
  send: (message: object) => Promise<void>;
  setup: () => Promise<void>;
  // Initiate an authenticated resume of the configured pairing.
  resume: () => Promise<void>;
  teardown: () => Promise<void>;

  status: Observable<Status>;
  peerKey: Observable<EncryptionKey | undefined>;
  peerCapabilities: Observable<PeerCapabilities | undefined>;
};
export type SignalingLayer = EventEmitter<SignalEventMap> & SignalingContext;
export type SignalingLayerFunction = (
  hooks: SignalingHooks,
) => Promise<SignalingLayer>;

export type CreateSignalingLayerFunction = (
  base: SignalingChannel,
) => SignalingLayerFunction;

/**
 * Base Signaling Layer implementation
 *
 * https://openlv.sh/api/signaling
 */
export const createSignalingLayer: CreateSignalingLayerFunction = channel => async (hooks: SignalingHooks) => {
  const {
    canEncrypt,
    encrypt,
    decrypt,
    capabilities,
    h,
    k: handshakeKey,
    publicKey,
    expectedPeerKey,
    resume: resumeConfig,
    isHost,
  } = hooks;

  const [status, setStatus] = observable<Status>(Status.STANDBY);
  const [peerKey, setPeerKey] = observable<EncryptionKey | undefined>(undefined);
  const [peerCapabilities, setPeerCapabilities] = observable<PeerCapabilities | undefined>(undefined);

  const emitter = new EventEmitter<SignalEventMap>();
  let isStopped = false;

  const fail = (reason: string) => {
    if (isStopped || status.get() === Status.ERROR) return;

    isStopped = true;
    resumeController?.teardown();
    setPeerKey(undefined);
    setPeerCapabilities(undefined);
    log(reason);
    emitter.emit("error", reason);
    setStatus(Status.ERROR);
  };

  const requireActive = () => {
    if (status.get() === Status.ERROR) {
      throw new Error("Signaling failed; pair again before reconnecting");
    }

    if (isStopped) throw new Error("Signaling has been torn down");
  };

  const { frame, parse } = handshake({
    isHost,
    handshakeKey,
    encrypt,
    decrypt,
  });

  const send = async (method: "handshake" | "encrypted", payload: SignalMessage) => {
    requireActive();

    const framed = await frame(method, payload);

    requireActive();
    await channel.publish(framed);
  };

  const resumeController = resumeConfig
    ? createResumeController({
        config: resumeConfig,
        publicKey,
        expectedPeerKey,
        getPeerKey: () => peerKey.get(),
        acceptPeerKey: setPeerKey,
        onResumed: () => {
          // Emit before flipping status so consumers can create a transport
          // before the ENCRYPTED handler runs.
          emitter.emit("resume");

          if (!isStopped) setStatus(Status.ENCRYPTED);
        },
        onFailure: fail,
        send: message => send("encrypted", message),
      })
    : undefined;

  const capabilitiesMessage = (): SignalMessage => ({
    type: "capabilities",
    payload: capabilities,
    timestamp: Date.now(),
  });
  const pubkeyMessage = (): SignalMessage => ({
    type: "pubkey",
    payload: { publicKey: publicKey.toString() },
    timestamp: Date.now(),
  });

  /**
   * A peer that restarts from the same URI re-runs the fresh handshake. An
   * already-encrypted peer must accept that and rebuild, otherwise a single
   * restart would leave both peers stalled on a dead transport.
   */
  const restartHandshake = () => {
    setPeerKey(undefined);
    setPeerCapabilities(undefined);
    emitter.emit("restart");
  };

  const handleHandshakeFrame = async (message: SignalMessage) => {
    await match({ msg: message, status: status.get(), isHost })
      .with({ msg: { type: "flash" }, status: Status.READY, isHost: true }, async () => {
        setStatus(Status.HANDSHAKE);
        await send("handshake", pubkeyMessage());
      })
      .with({ msg: { type: "flash" }, isHost: true }, async () => {
        restartHandshake();
        setStatus(Status.HANDSHAKE);
        await send("handshake", pubkeyMessage());
      })
      // A restarting host re-sends its pubkey. Accept it from any non-READY
      // state so a client that is still ENCRYPTED can restart the handshake.
      .with(
        { msg: { type: "pubkey" }, isHost: false },
        async ({ msg: { payload: messagePayload } }) => {
          let receivedKey: EncryptionKey;

          try {
            receivedKey = await parseEncryptionKey(messagePayload.publicKey);

            if (!await validatePublicKeyHash(receivedKey, h)) {
              fail("Received host public key does not match expected hash; pair again");

              return;
            }

            if (expectedPeerKey && receivedKey.toString() !== expectedPeerKey.toString()) {
              fail("Received host public key does not match saved pairing; pair again");

              return;
            }
          }
          catch {
            fail("Failed to parse received host public key; pair again");

            return;
          }

          if (isStopped) return;

          if (status.get() === Status.ENCRYPTED) {
            restartHandshake();
          }

          if (!setPeerKey(receivedKey)) return;

          if (!setStatus(Status.HANDSHAKE_PARTIAL)) return;

          return await send("encrypted", pubkeyMessage());
        },
      )
      .otherwise(() => {
        log("Ignoring handshake frame", message.type, "in status", status.get());
      });
  };

  const handleEncryptedFrame = async (message: SignalMessage) => {
    await match({ msg: message, status: status.get(), isHost })
      // Host: client responded with its public key.
      .with(
        { msg: { type: "pubkey" }, isHost: true, status: Status.HANDSHAKE },
        async ({ msg: { payload: messagePayload } }) => {
          let receivedKey: EncryptionKey;

          try {
            receivedKey = await parseEncryptionKey(messagePayload.publicKey);
          }
          catch {
            fail("Failed to parse received client public key; pair again");

            return;
          }

          if (isStopped) return;

          if (expectedPeerKey && receivedKey.toString() !== expectedPeerKey.toString()) {
            fail("Received client public key does not match saved pairing; pair again");

            return;
          }

          if (!setPeerKey(receivedKey)) return;

          setStatus(Status.HANDSHAKE_PARTIAL);

          return await send("encrypted", capabilitiesMessage());
        },
      )
      .with(
        { msg: { type: "capabilities" }, status: Status.HANDSHAKE_PARTIAL },
        async ({ msg: { payload: messagePayload } }) => {
          setPeerCapabilities(messagePayload);
          setStatus(Status.ENCRYPTED);

          if (isHost) return;

          return await send("encrypted", capabilitiesMessage());
        },
      )
      // Client already encrypted, but the host is still re-sending its
      // capabilities (our final packet was lost): answer again so the host
      // can finish.
      .with(
        { msg: { type: "capabilities" }, status: Status.ENCRYPTED, isHost: false },
        async () => await send("encrypted", capabilitiesMessage()),
      )
      .with({ msg: { type: "data" }, status: Status.ENCRYPTED }, async () => {
        emitter.emit("message", message.payload as object);
      })
      // A resume may arrive in any stage: an already-ENCRYPTED peer must
      // still accept a restarting peer and renegotiate the transport.
      .with({ msg: { type: "resume" } }, async ({ msg }) => await resumeController?.handleResume(msg))
      .with({ msg: { type: "resume-ack" } }, async ({ msg }) => await resumeController?.handleResumeAck(msg))
      .with({ msg: { type: "resume-confirm" } }, async ({ msg }) => await resumeController?.handleResumeConfirm(msg))
      .otherwise(() => {
        log("Ignoring encrypted frame", message.type, "in status", status.get());
      });
  };

  const onReceive = async (payload: string) => {
    if (isStopped || status.get() === Status.ERROR) return;

    let parsed: [SignalingStage, SignalMessage] | undefined;

    try {
      parsed = await parse(payload);
    }
    catch (error) {
      log("Dropping undecryptable or malformed frame", error);

      return;
    }

    if (!parsed || isStopped || status.get() === Status.ERROR) return;

    const [stage, message] = parsed;

    try {
      if (stage === XR_H_PREFIX) return await handleHandshakeFrame(message);

      if (stage === XR_PREFIX) return await handleEncryptedFrame(message);

      log("Dropping frame with unknown prefix");
    }
    catch (error) {
      if (!isStopped) fail(`Signaling authentication failed: ${error instanceof Error ? error.message : String(error)}; pair again`);
    }
  };

  const setup = async () => {
    requireActive();
    setStatus(Status.CONNECTING);
    await channel.setup();

    if (isStopped) return;

    await channel.subscribe(onReceive);

    if (isStopped) return;

    if (canEncrypt()) {
      setStatus(Status.ENCRYPTED);

      return;
    }

    setStatus(Status.READY);

    if (resumeController?.initiate) {
      // Resume is initiated explicitly so both peers are subscribed first;
      // the fresh handshake must not run for a resumed pairing.
      return;
    }

    if (!isHost) {
      // Enter HANDSHAKE before publishing: the host's pubkey reply can
      // arrive while the publish is still in flight.
      setStatus(Status.HANDSHAKE);
      await send("handshake", {
        type: "flash",
        payload: {},
        timestamp: Date.now(),
      });
    }
  };

  const teardown = async () => {
    log("teardown");
    isStopped = true;
    resumeController?.teardown();
    await channel.teardown?.();
  };

  const resume = async () => {
    requireActive();

    if (!resumeController) {
      throw new Error("No pairing state available to resume");
    }

    if (status.get() !== Status.ENCRYPTED) {
      setStatus(Status.HANDSHAKE_PARTIAL);
    }

    await resumeController.resume();
  };

  return make(emitter, {
    type: channel.type,
    setup,
    resume,
    teardown,
    send(message: object) {
      if (isStopped || status.get() === Status.ERROR) {
        return Promise.reject(new Error("Signaling failed or closed; pair again before sending"));
      }

      if (!canEncrypt()) {
        return Promise.reject(
          new Error("Cannot encrypt message before keys are exchanged"),
        );
      }

      return send("encrypted", {
        type: "data",
        payload: message,
        timestamp: Date.now(),
      });
    },
    status,
    peerKey,
    peerCapabilities,
  });
};
