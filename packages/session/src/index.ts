/* eslint-disable max-lines */
import {
  decodeConnectionURL,
  type Observable,
  observable,
  OPENLV_PROTOCOL_VERSION,
  parseSessionConnectionParameters,
  type SerializedEncryptionKey,
  SESSION_CONNECTION_PARAMETER_KEYS,
  SESSION_SETUP_TIMEOUT_MS,
  type SessionConnectionParameters,
  type SessionHandshakeParameters,
  type SessionLinkParameters,
  validateSessionConnectionKeys,
} from "@openlv/core";
import {
  deriveSymmetricKey,
  generateHandshakeKey,
  generateSessionId,
  initEncryptionKeys,
  initHash,
} from "@openlv/core/encryption";
import {
  type PeerCapabilities,
  type PeerInfo,
  type SignalingLayer,
  type SignalingResumeState,
  Status as SignalStatus,
  validatePeerInfo,
} from "@openlv/signaling";
import {
  Status as TransportStatus,
  type TransportLayer,
  type TransportLayerFunction,
} from "@openlv/transport";
import { EventEmitter } from "eventemitter3";

import { loadSignaling } from "./dynamic.js";
import type { SessionEvents } from "./events.js";
import { awaitCorrelatedResponse, type CorrelationEvents } from "./messages/correlate.js";
import type { SessionMessage } from "./messages/index.js";
import { createSessionMessaging } from "./messages/route.js";
import { log } from "./utils/log.js";

export { loadSignaling, loadTransport } from "./dynamic.js";
export type { PeerInfo } from "@openlv/signaling";

export const SessionStatus = {
  CREATED: "created",
  SIGNALING: "signaling",
  READY: "ready",
  LINKING: "linking",
  CONNECTED: "connected",
  DISCONNECTED: "disconnected",
} as const;
export type SessionStatus = (typeof SessionStatus)[keyof typeof SessionStatus];

export class InvalidSavedSessionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidSavedSessionError";
  }
}

export type SessionOptions = {
  info?: PeerInfo;
  /** Called synchronously before a resumed counter is sent. */
  onConnectionParametersChange?: (
    parameters: SessionConnectionParameters,
  ) => void;
};

/**
 * an OpenLV Session
 *
 * https://openlv.sh/api/session
 */
export type Session = {
  status: Observable<SessionStatus>;
  signalStatus: Observable<SignalStatus>;
  error: Observable<string | undefined>;
  peerInfo: Observable<PeerInfo | undefined>;
  getHandshakeParameters(): SessionHandshakeParameters;
  getConnectionParameters(): SessionConnectionParameters;
  connect(): Promise<void>;
  /** Close the pairing, or release local resources without unpairing the peer. */
  close(options?: { notifyPeer?: boolean; }): Promise<void>;
  send(message: object, ackTimeout?: number, responseTimeout?: number): Promise<unknown>;
  emitter: EventEmitter<SessionEvents>;
  _internal: {
    signal: SignalingLayer;
    /** True when signaling or resume deadlines make the saved pairing unusable. */
    isPairingInvalidated: boolean;
    /** Instantiated when signaling reaches ENCRYPTED and a transport is selected. */
    transport: TransportLayer | undefined;
  };
};

/**
 * OpenLV Session
 *
 * https://openlv.sh/api/session
 */
export const createSession = async (
  initParameters: SessionLinkParameters,
  transportLayers: TransportLayerFunction[],
  onMessage: (message: object) => Promise<object | string>,
  options?: SessionOptions,
): Promise<Session> => {
  if (transportLayers.length === 0) {
    throw new Error("At least one transport is required");
  }

  if (options?.info) {
    const problem = validatePeerInfo(options.info);

    if (problem) throw new Error(`Invalid session info: ${problem}`);
  }

  const savedConnection = parseSessionConnectionParameters(initParameters);
  const hasConnectionMaterial = SESSION_CONNECTION_PARAMETER_KEYS.some(
    key => Object.hasOwn(initParameters, key),
  );

  if (hasConnectionMaterial && !savedConnection) {
    throw new InvalidSavedSessionError(
      "Invalid saved session. Request a fresh pairing URI and try again.",
    );
  }

  if (savedConnection && !options?.onConnectionParametersChange) {
    throw new Error("Resuming a saved session requires durable connection parameter persistence");
  }

  if (savedConnection && !await validateSessionConnectionKeys(savedConnection)) {
    throw new InvalidSavedSessionError(
      "Saved session key material is inconsistent. Request a fresh pairing URI and try again.",
    );
  }

  const emitter = new EventEmitter<SessionEvents>();
  const messages = new EventEmitter<CorrelationEvents>();
  const sessionId
    = "sessionId" in initParameters
      ? initParameters.sessionId
      : generateSessionId();
  const {
    encryptionKey,
    decryptionKey,
    relyingEncryptionKey,
  } = await initEncryptionKeys(initParameters);
  const { decrypt } = decryptionKey;
  const handshakeKey
    = "k" in initParameters
      ? await deriveSymmetricKey(initParameters.k)
      : await generateHandshakeKey();
  const { hash, isHost } = await initHash(
    "h" in initParameters ? initParameters.h : undefined,
    encryptionKey,
  );
  const protocol = initParameters.p;
  const server = initParameters.s;
  const capabilities: PeerCapabilities = {
    transports: transportLayers.map(layer => layer.transportId),
    ...(options?.info && { info: options.info }),
  };
  const handshakeParameters: SessionHandshakeParameters = {
    version: OPENLV_PROTOCOL_VERSION,
    sessionId,
    h: hash,
    k: handshakeKey.toString(),
    p: protocol,
    s: server,
  };
  const getHandshakeParameters = () => ({ ...handshakeParameters });

  let resumeState: SignalingResumeState = {
    pairingId: savedConnection?.pairingId ?? sessionId,
    lastCounter: savedConnection?.lastCounter ?? 0,
    lastSeenCounter: savedConnection?.lastSeenCounter ?? 0,
    lastSeenAckCounter: savedConnection?.lastSeenAckCounter ?? 0,
  };
  const isResuming = savedConnection !== undefined;
  // Either side may be the one that reloaded, so both must be able to initiate.
  // Simultaneous resumes are de-duplicated by the pairing counter and challenge
  // state machine, and completing either direction marks the session resumed.
  const shouldInitiateResume = isResuming;
  let selectedTransportId = savedConnection?.transportId;
  const persistResumeState = (state: SignalingResumeState) => {
    options?.onConnectionParametersChange?.(buildConnectionParameters(state));
    resumeState = state;
  };

  const [status, setStatus] = observable<SessionStatus>(SessionStatus.CREATED);
  const [lastError, setLastError] = observable<string | undefined>(undefined);
  let isPairingInvalidated = false;
  const [peerInfo, setPeerInfo] = observable<PeerInfo | undefined>(undefined);

  const setLastErrorIfUnset = (reason: string) => {
    if (lastError.get() === undefined) setLastError(reason);
  };

  // Any open send() must reject when the session ends, otherwise callers wait
  // out the full response timeout.
  status.subscribe((current) => {
    if (current === SessionStatus.DISCONNECTED) {
      messages.emit("ended", lastError.get() ?? "Session closed");
    }
  });

  const signalLayer = await loadSignaling(protocol);
  const signaling = await signalLayer({
    topic: sessionId,
    url: server,
  });
  const encrypt = async (message: string) => {
    // Only resume signaling sends before the pinned peer is authenticated.
    const key = signal.peerKey.get() ?? relyingEncryptionKey;

    if (!key) {
      throw new Error("Relying party public key not found");
    }

    return await key.encrypt(message);
  };
  const signal = await signaling({
    h: hash,
    canEncrypt: () => signal.peerKey.get() !== undefined,
    encrypt,
    decrypt,
    publicKey: encryptionKey,
    expectedPeerKey: relyingEncryptionKey,
    resume: {
      ...resumeState,
      initiate: shouldInitiateResume,
      persist: persistResumeState,
    },
    k: handshakeKey,
    capabilities,
    initialPeerCapabilities: savedConnection?.peerCapabilities,
    isHost,
  });
  const buildConnectionParameters = (
    state: SignalingResumeState,
  ): SessionConnectionParameters => {
    const relyingPublicKey = signal.peerKey.get() ?? relyingEncryptionKey;

    if (!relyingPublicKey) {
      throw new Error("Cannot save session before the peer key is exchanged");
    }

    if (!selectedTransportId) {
      throw new Error("Cannot save session before transport negotiation");
    }

    return {
      ...handshakeParameters,
      relyingPublicKey: relyingPublicKey.toString() as SerializedEncryptionKey,
      encryptionKey: encryptionKey.toString() as SerializedEncryptionKey,
      decryptionKey: decryptionKey.toString() as SerializedEncryptionKey,
      ...state,
      transportId: selectedTransportId,
      peerCapabilities: signal.peerCapabilities.get() ?? savedConnection?.peerCapabilities,
    };
  };

  signal.peerCapabilities.subscribe(received => setPeerInfo(received?.info));

  let transport: TransportLayer | undefined;
  // The peer can start renegotiating as soon as it observes our resume, which
  // can be before this side has finished building its transport; the messaging
  // layer buffers those negotiation frames instead of dropping them.
  let isTransportReady = false;

  // Bound resumed setup immediately, but allow fresh hosts to advertise until a peer joins.
  let linkDeadline: number | undefined;
  let unsubscribeTransportStatus: (() => void) | undefined;
  let unsubscribeSignalStatus: (() => void) | undefined;
  let isStopped = false;
  let teardownPromise: Promise<void> | undefined;
  let rejectPendingConnect: ((error: Error) => void) | undefined;
  const teardown = () => {
    if (teardownPromise) return teardownPromise;

    isStopped = true;
    clearLinkDeadline();
    rejectPendingConnect?.(new Error(lastError.get() ?? "Session closed"));
    signal.off("message", messaging.handleSignalMessage);
    signal.off("resume", onSignalResume);
    signal.off("error", onSignalError);
    unsubscribeSignalStatus?.();
    unsubscribeSignalStatus = undefined;
    unsubscribeTransportStatus?.();
    unsubscribeTransportStatus = undefined;
    const closingTransport = transport;

    transport = undefined;
    isTransportReady = false;
    messaging.clearNegotiation();
    closingTransport?.emitter.off("error", onTransportError);
    teardownPromise = (async () => {
      try {
        await Promise.all([
          closingTransport?.teardown(),
          signal.teardown(),
        ]);
      }
      catch (error) {
        log("session teardown failed", error);
        setLastErrorIfUnset(error instanceof Error ? error.message : "Session teardown failed");
      }
    })();
    setStatus(SessionStatus.DISCONNECTED);

    return teardownPromise;
  };

  const clearLinkDeadline = () => {
    clearTimeout(linkDeadline);
    linkDeadline = undefined;
  };

  const messaging = createSessionMessaging({
    onMessage,
    emitter,
    messages,
    getTransport: () => transport,
    isTransportReady: () => isTransportReady,
    isStopped: () => isStopped,
    close: teardown,
  });

  const onTransportStateChange = (transportStatus: TransportStatus) => {
    if (isStopped) return;

    if (transportStatus === TransportStatus.CONNECTED) {
      clearLinkDeadline();
      setLastError(undefined);
      setStatus(SessionStatus.CONNECTED);
    }

    if (transportStatus === TransportStatus.ERROR) {
      clearLinkDeadline();
      setLastErrorIfUnset("Peer-to-peer transport failed");
      setStatus(SessionStatus.DISCONNECTED);
    }
  };

  const onTransportError = (reason?: string) => {
    if (reason) setLastError(reason);
  };

  const armLinkDeadline = () => {
    linkDeadline ??= setTimeout(() => {
      if (status.get() === SessionStatus.CONNECTED) return;

      if (isResuming) {
        log("session resumption failed to complete in time");
        setLastErrorIfUnset("Session resumption timed out. Retry or request a fresh pairing URI.");
      }
      else {
        log("transport failed to connect in time");
        setLastErrorIfUnset("Timed out establishing the peer-to-peer connection");
      }

      void teardown();
    }, SESSION_SETUP_TIMEOUT_MS);
  };

  const onTransportSetupError = (error: unknown) => {
    if (isStopped) return;

    log("transport setup failed", error);
    clearLinkDeadline();
    setLastErrorIfUnset(error instanceof Error ? error.message : "Transport setup failed");
    setStatus(SessionStatus.DISCONNECTED);
  };

  const startTransport = async () => {
    if (isStopped || transport || !signal.peerKey.get()) return;

    const peerCapabilities = signal.peerCapabilities.get();
    let transportId = selectedTransportId;

    if (!transportId && peerCapabilities) {
      const hostPreference = isHost ? capabilities.transports : peerCapabilities.transports;
      const clientSupported = isHost ? peerCapabilities.transports : capabilities.transports;

      transportId = hostPreference.find(candidate => clientSupported.includes(candidate));
    }

    const layer = transportLayers.find(layer => layer.transportId === transportId);

    if (!layer) {
      log("no common transport with peer", capabilities.transports, peerCapabilities?.transports);
      setLastErrorIfUnset("No common transport with peer");
      await teardown();

      return;
    }

    selectedTransportId = layer.transportId;
    transport = layer.create({
      encrypt,
      decrypt,
      isHost,
      onmessage: messaging.handleTransportMessage,
      async subsend(message) {
        await signal.send({
          type: "request",
          messageId: crypto.randomUUID(),
          payload: message,
        } satisfies SessionMessage);
      },
    });
    transport.emitter.on("error", onTransportError);
    unsubscribeTransportStatus = transport.status.subscribe(onTransportStateChange);
    armLinkDeadline();
    await transport.setup();
    isTransportReady = true;
    await messaging.flushNegotiation();
  };

  const onSignalResume = async () => {
    if (isStopped) return;

    try {
      setStatus(SessionStatus.LINKING);

      if (transport) {
        armLinkDeadline();
        isTransportReady = false;
        await transport.renegotiate();
        isTransportReady = true;
        await messaging.flushNegotiation();
      }
      else {
        await startTransport();
      }
    }
    catch (error) {
      onTransportSetupError(error);
    }
  };

  const onSignalError = (reason: string, shouldInvalidatePairing = false) => {
    isPairingInvalidated ||= shouldInvalidatePairing;
    setLastError(reason);
  };

  const onSignalStateChange = (signalStatus: SignalStatus) => {
    if (isStopped) return;

    if (signalStatus === SignalStatus.READY) {
      setStatus(SessionStatus.READY);
    }

    if (signalStatus === SignalStatus.HANDSHAKE || signalStatus === SignalStatus.HANDSHAKE_PARTIAL) {
      setStatus(SessionStatus.LINKING);
    }

    if (signalStatus === SignalStatus.ENCRYPTED) {
      void startTransport().catch(onTransportSetupError);
    }

    if (signalStatus === SignalStatus.ERROR) {
      setLastErrorIfUnset("Signaling failed or timed out");
      void teardown();
    }
  };

  return {
    connect: async () => {
      if (isStopped) throw new Error("Session closed");

      setStatus(SessionStatus.SIGNALING);

      signal.on("message", messaging.handleSignalMessage);
      signal.on("resume", onSignalResume);
      signal.on("error", onSignalError);
      unsubscribeSignalStatus = signal.status.subscribe(onSignalStateChange);

      // eslint-disable-next-line unicorn/prefer-promise-with-resolvers -- Project libraries stop at ES2022.
      const ended = new Promise<never>((_resolve, reject) => {
        rejectPendingConnect = reject;
      });

      if (isResuming) armLinkDeadline();

      try {
        await Promise.race([
          (async () => {
            await signal.setup();

            if (isStopped) {
              await signal.teardown();

              return;
            }

            if (shouldInitiateResume) {
              await signal.resume();
            }
          })(),
          ended,
        ]);
      }
      catch (error) {
        setLastErrorIfUnset(error instanceof Error ? error.message : "Signaling setup failed");
        void teardown();

        throw error;
      }
      finally {
        rejectPendingConnect = undefined;
      }
    },
    async close({ notifyPeer = true } = {}) {
      if (notifyPeer && transport) {
        try {
          await transport.send({ type: "close" } satisfies SessionMessage);
        }
        catch (error) {
          log("failed to send close to peer", error);
        }
      }

      await teardown();
    },
    status,
    signalStatus: signal.status,
    error: lastError,
    peerInfo,
    getHandshakeParameters,
    getConnectionParameters: () => buildConnectionParameters(resumeState),
    async send(
      message: object,
      ackTimeout: number = 10_000,
      responseTimeout: number = 60 * 60_000,
    ) {
      if (!transport || signal.status.get() !== SignalStatus.ENCRYPTED) {
        throw new Error("Session not ready");
      }

      const messageId = crypto.randomUUID();
      const sessionMessage: SessionMessage = {
        type: "request",
        messageId,
        payload: message,
      };

      await transport.send(sessionMessage);

      return awaitCorrelatedResponse(messages, messageId, ackTimeout, responseTimeout);
    },
    _internal: {
      signal,
      get isPairingInvalidated() {
        return isPairingInvalidated;
      },
      get transport() {
        return transport;
      },
    },
    emitter,
  };
};

/**
 * Connect to a session from its openlv:// URL
 */
export const connectSession = async (
  connectionUrl: string,
  onMessage: (message: object) => Promise<object | string>,
  transports: TransportLayerFunction[],
  options?: SessionOptions,
): Promise<Session> => {
  const initParameters = decodeConnectionURL(connectionUrl);

  return createSession(initParameters, transports, onMessage, options);
};
