/* eslint-disable max-lines */
import {
  decodeConnectionURL,
  type Observable,
  observable,
  OPENLV_PROTOCOL_VERSION,
  parseSessionConnectionParameters,
  type SessionConnectionParameters,
  type SessionHandshakeParameters,
  type SessionLinkParameters,
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
  type TransportMessage,
} from "@openlv/transport";
import { EventEmitter } from "eventemitter3";

import { loadSignaling } from "./dynamic.js";
import type { SessionEvents } from "./events.js";
import { awaitCorrelatedResponse, type CorrelationEvents } from "./messages/correlate.js";
import type {
  SessionMessage,
  SessionMessageAck,
  SessionMessageRequest,
  SessionMessageResponse,
} from "./messages/index.js";
import { respondToRequest } from "./messages/index.js";
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
  close(): Promise<void>;
  send(message: object, ackTimeout?: number, responseTimeout?: number): Promise<unknown>;
  emitter: EventEmitter<SessionEvents>;
  _internal: {
    signal: SignalingLayer;
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
  const hasConnectionMaterial
    = "encryptionKey" in initParameters
      || "decryptionKey" in initParameters
      || "relyingPublicKey" in initParameters
      || "pairingId" in initParameters
      || "transportId" in initParameters
      || "lastCounter" in initParameters
      || "lastSeenCounter" in initParameters
      || "lastSeenAckCounter" in initParameters;

  if (hasConnectionMaterial && !savedConnection) {
    throw new Error("Invalid saved session. Request a fresh pairing URI and try again.");
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

  let resumeState: SignalingResumeState = {
    pairingId: savedConnection?.pairingId ?? sessionId,
    lastCounter: savedConnection?.lastCounter ?? 0,
    lastSeenCounter: savedConnection?.lastSeenCounter ?? 0,
    lastSeenAckCounter: savedConnection?.lastSeenAckCounter ?? 0,
  };
  const isResuming = savedConnection !== undefined;
  let selectedTransportId = savedConnection?.transportId;
  const persistResumeState = (state: SignalingResumeState) => {
    resumeState = state;
    options?.onConnectionParametersChange?.(connectionParameters());
  };

  const [status, setStatus] = observable<SessionStatus>(SessionStatus.CREATED);
  const [lastError, setLastError] = observable<string | undefined>(undefined);
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
      initiate: isResuming,
      persist: persistResumeState,
    },
    k: handshakeKey,
    capabilities,
    isHost,
  });

  signal.peerCapabilities.subscribe(received => setPeerInfo(received?.info));

  let transport: TransportLayer | undefined;
  const connectionParameters = (): SessionConnectionParameters => {
    const relyingPublicKey = signal.peerKey.get() ?? relyingEncryptionKey;

    if (!relyingPublicKey) {
      throw new Error("Cannot save session before the peer key is exchanged");
    }

    if (!selectedTransportId) {
      throw new Error("Cannot save session before transport negotiation");
    }

    return {
      version: OPENLV_PROTOCOL_VERSION,
      sessionId,
      h: hash,
      k: handshakeKey.toString(),
      p: protocol,
      s: server,
      relyingPublicKey: relyingPublicKey.toString(),
      encryptionKey: encryptionKey.toString(),
      decryptionKey: decryptionKey.toString(),
      ...resumeState,
      transportId: selectedTransportId,
    };
  };

  // Bound resumed setup immediately, but allow fresh hosts to advertise until a peer joins.
  const TRANSPORT_LINK_TIMEOUT_MS = 45_000;
  let linkDeadline: ReturnType<typeof setTimeout> | undefined;
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
    signal.off("message", onSignalMessage);
    signal.off("resume", onSignalResume);
    signal.off("error", onSignalError);
    unsubscribeSignalStatus?.();
    unsubscribeSignalStatus = undefined;
    unsubscribeTransportStatus?.();
    unsubscribeTransportStatus = undefined;
    const closingTransport = transport;

    transport = undefined;
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
        setLastErrorIfUnset("Session resumption timed out. Request a fresh pairing URI and try again.");
      }
      else {
        log("transport failed to connect in time");
        setLastErrorIfUnset("Timed out establishing the peer-to-peer connection");
      }

      void teardown();
    }, TRANSPORT_LINK_TIMEOUT_MS);
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
      async onmessage(message) {
        if (isStopped) return;

        try {
          if (message.type === "close") {
            await teardown();

            return;
          }

          if (transport && message.type === "request") {
            await respondToRequest(message as SessionMessageRequest, transport, onMessage, emitter);
          }
          else if (message.type === "response" || message.type === "ack") {
            messages.emit("message", message as SessionMessageAck | SessionMessageResponse);
          }
        }
        catch (error) {
          log("failed to handle peer message", error);
        }
      },
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
  };

  const onSignalResume = async () => {
    if (isStopped) return;

    try {
      setStatus(SessionStatus.LINKING);

      if (transport) {
        armLinkDeadline();
        await transport.renegotiate();
      }
      else {
        await startTransport();
      }
    }
    catch (error) {
      onTransportSetupError(error);
    }
  };

  const onSignalError = (reason: string) => setLastError(reason);

  const onSignalMessage = async (message: object) => {
    if (isStopped) return;

    const sessionMessage = message as SessionMessage;

    if (sessionMessage.type === "response") {
      messages.emit("message", sessionMessage);
    }
    else if (sessionMessage.type === "request") {
      if (!transport) return;

      try {
        await transport.handle(sessionMessage.payload as TransportMessage);
      }
      catch (error) {
        log("failed to handle negotiation message", error);
      }
    }
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

      signal.on("message", onSignalMessage);
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

            if (isResuming) {
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
    async close() {
      try {
        await transport?.send({ type: "close" } satisfies SessionMessage);
      }
      catch (error) {
        log("failed to send close to peer", error);
      }

      await teardown();
    },
    status,
    signalStatus: signal.status,
    error: lastError,
    peerInfo,
    getHandshakeParameters() {
      return {
        version: OPENLV_PROTOCOL_VERSION,
        sessionId,
        h: hash,
        k: handshakeKey.toString(),
        p: protocol,
        s: server,
      };
    },
    getConnectionParameters: connectionParameters,
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
