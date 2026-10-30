import {
  decodeConnectionURL,
  type Observable,
  observable,
  OPENLV_PROTOCOL_VERSION,
  parseSessionConnectionParameters,
  type PeerCapabilities,
  type PeerInfo,
  type SerializedEncryptionKey,
  SESSION_CONNECTION_PARAMETER_KEYS,
  type SessionConnectionParameters,
  type SessionHandshakeParameters,
  type SessionLinkParameters,
  validatePeerInfo,
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
  type SignalingLayer,
  Status as SignalStatus,
} from "@openlv/signaling";
import {
  type TransportLayer,
  type TransportLayerFunction,
} from "@openlv/transport";
import { EventEmitter } from "eventemitter3";

import { loadSignaling } from "./dynamic.js";
import type { SessionEvents } from "./events.js";
import { createSessionLifecycle } from "./lifecycle.js";
import { awaitCorrelatedResponse, type CorrelationEvents } from "./messages/correlate.js";
import type { SessionMessage } from "./messages/index.js";
import { createSessionMessaging } from "./messages/route.js";
import { createSessionTransport } from "./transport.js";
import { log } from "./utils/log.js";

export { loadSignaling, loadTransport } from "./dynamic.js";
export { RequestFailedError } from "./messages/correlate.js";
export type { SessionMessage } from "./messages/index.js";

// `peerInfo` is part of the session's surface, so consumers can name its type here.
export type { PeerInfo } from "@openlv/core";

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
  /** Called when authenticated connection parameters are available or change. */
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
  send(
    message: unknown,
    ackTimeout?: number,
    responseTimeout?: number,
  ): Promise<unknown>;
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
  onMessage: (message: unknown) => Promise<unknown>,
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

  const isResuming = savedConnection !== undefined;
  let resumptionSecret = savedConnection?.resumptionSecret;
  let transportChannel: {
    send: { encrypt: (message: string) => Promise<string>; };
    receive: { decrypt: (message: string) => Promise<string>; };
  } | undefined;

  const [status, setStatus] = observable<SessionStatus>(SessionStatus.CREATED);
  const [lastError, setLastError] = observable<string | undefined>(undefined);
  const [peerInfo, setPeerInfo] = observable<PeerInfo | undefined>(undefined);

  const setLastErrorIfUnset = (reason: string) => {
    if (lastError.get() === undefined) setLastError(reason);
  };

  const lifecycle = createSessionLifecycle({
    emitter,
    lastError,
    setLastErrorIfUnset,
    onDisconnected: () => setStatus(SessionStatus.DISCONNECTED),
    teardownLayers: async () => {
      await Promise.all([
        sessionTransport.teardown(),
        signal.teardown(),
      ]);
    },
  });

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
  const encrypt = (message: string) => {
    if (!transportChannel) throw new Error("Peer has not been authenticated");

    return transportChannel.send.encrypt(message);
  };
  const decrypt = (message: string) => {
    if (!transportChannel) throw new Error("Peer has not been authenticated");

    return transportChannel.receive.decrypt(message);
  };
  const signal = await signaling({
    h: hash,
    sessionId,
    secretKey: decryptionKey.toString(),
    publicKey: encryptionKey,
    expectedPeerKey: relyingEncryptionKey,
    resumptionSecret,
    k: handshakeKey,
    capabilities,
    isHost,
  });
  const buildConnectionParameters = (): SessionConnectionParameters => {
    const relyingPublicKey = signal.peerKey.get() ?? relyingEncryptionKey;

    if (!relyingPublicKey) {
      throw new Error("Cannot save session before the peer key is exchanged");
    }

    if (!sessionTransport.selectedTransportId) {
      throw new Error("Cannot save session before transport negotiation");
    }

    if (!resumptionSecret) {
      throw new Error("Cannot save session before the peer is authenticated");
    }

    return {
      ...handshakeParameters,
      relyingPublicKey: relyingPublicKey.toString() as SerializedEncryptionKey,
      encryptionKey: encryptionKey.toString() as SerializedEncryptionKey,
      decryptionKey: decryptionKey.toString() as SerializedEncryptionKey,
      resumptionSecret,
      transportId: sessionTransport.selectedTransportId,
      peerCapabilities: signal.peerCapabilities.get() ?? savedConnection?.peerCapabilities,
    };
  };

  signal.peerCapabilities.subscribe(received => setPeerInfo(received?.info));

  const messaging = createSessionMessaging({
    onMessage,
    emitter,
    messages,
    getTransport: () => sessionTransport.transport,
    isTransportReady: () => sessionTransport.isReady,
    isStopped: lifecycle.isStopped,
    close: lifecycle.teardown,
  });

  const onTransportError = (reason?: string) => {
    if (reason) setLastError(reason);
  };

  const onTransportConnected = () => {
    setLastError(undefined);
    options?.onConnectionParametersChange?.(buildConnectionParameters());
    setStatus(SessionStatus.CONNECTED);
  };

  const onTransportDisconnected = () => {
    setLastErrorIfUnset("Peer-to-peer transport failed");
    setStatus(SessionStatus.DISCONNECTED);
  };

  const onTransportSetupError = (error: unknown, hasTransport: boolean) => {
    if (lifecycle.isStopped()) return;

    log("transport setup failed", error);
    setLastErrorIfUnset(error instanceof Error ? error.message : "Transport setup failed");
    setStatus(SessionStatus.DISCONNECTED);

    if (!hasTransport) void lifecycle.teardown();
  };

  const onTransportTimeout = (isResumingAttempt: boolean) => {
    if (isResumingAttempt) {
      log("session resumption failed to complete in time");
      setLastErrorIfUnset("Session resumption timed out. Retry or request a fresh pairing URI.");
    }
    else {
      log("transport failed to connect in time");
      setLastErrorIfUnset("Timed out establishing the peer-to-peer connection");
    }

    void lifecycle.teardown();
  };

  const sessionTransport = createSessionTransport({
    transportLayers,
    capabilities,
    signal,
    isHost,
    selectedTransportId: savedConnection?.transportId,
    encrypt,
    decrypt,
    onmessage: messaging.handleTransportMessage,
    isStopped: lifecycle.isStopped,
    isConnected: () => status.get() === SessionStatus.CONNECTED,
    isResuming,
    flushNegotiation: messaging.flushNegotiation,
    onConnected: onTransportConnected,
    onDisconnected: onTransportDisconnected,
    onError: onTransportError,
    onSetupError: onTransportSetupError,
    onTimeout: onTransportTimeout,
  });

  const onSignalHandshake = (
    result: { transport: NonNullable<typeof transportChannel>; resumptionSecret: string; },
    isRestart: boolean,
  ) => {
    transportChannel = result.transport;
    resumptionSecret = result.resumptionSecret;

    if (lifecycle.isStopped()) return;

    if (isRestart) {
      setStatus(SessionStatus.LINKING);
      sessionTransport.resume();
    }
  };

  const onSignalError = (reason: string, shouldInvalidatePairing = false) => {
    if (shouldInvalidatePairing) lifecycle.invalidatePairing();

    setLastError(reason);
  };

  const onSignalStateChange = (signalStatus: SignalStatus) => {
    if (lifecycle.isStopped()) return;

    if (signalStatus === SignalStatus.READY) {
      setStatus(SessionStatus.READY);
    }

    if (signalStatus === SignalStatus.HANDSHAKE || signalStatus === SignalStatus.HANDSHAKE_PARTIAL) {
      setStatus(SessionStatus.LINKING);
    }

    if (signalStatus === SignalStatus.ENCRYPTED) {
      void sessionTransport.start();
    }

    if (signalStatus === SignalStatus.ERROR) {
      setLastErrorIfUnset("Signaling failed or timed out");
      void lifecycle.teardown();
    }
  };

  return {
    connect: async () => {
      if (lifecycle.isStopped()) throw new Error("Session closed");

      setStatus(SessionStatus.SIGNALING);

      signal.on("message", messaging.handleSignalMessage);
      signal.on("handshake", onSignalHandshake);
      signal.on("error", onSignalError);
      const unsubscribeSignalStatus = signal.status.subscribe(onSignalStateChange);

      lifecycle.onTeardown(() => {
        signal.off("message", messaging.handleSignalMessage);
        signal.off("handshake", onSignalHandshake);
        signal.off("error", onSignalError);
        unsubscribeSignalStatus();
        messaging.clearNegotiation();
      });

      if (isResuming) sessionTransport.armLinkDeadline();

      try {
        await lifecycle.trackConnect(async () => {
          await signal.setup();

          if (lifecycle.isStopped()) {
            await signal.teardown();

            return;
          }
        });
      }
      catch (error) {
        setLastErrorIfUnset(error instanceof Error ? error.message : "Signaling setup failed");
        void lifecycle.teardown();

        throw error;
      }
    },
    async close({ notifyPeer = true } = {}) {
      if (notifyPeer && sessionTransport.transport) {
        try {
          await sessionTransport.transport.send({ type: "close" } satisfies SessionMessage);
        }
        catch (error) {
          log("failed to send close to peer", error);
        }
      }

      await lifecycle.teardown();
    },
    status,
    signalStatus: signal.status,
    error: lastError,
    peerInfo,
    getHandshakeParameters,
    getConnectionParameters: buildConnectionParameters,
    async send(
      message: unknown,
      ackTimeout: number = 10_000,
      responseTimeout: number = 60 * 60_000,
    ) {
      if (!sessionTransport.transport || status.get() !== SessionStatus.CONNECTED || signal.status.get() !== SignalStatus.ENCRYPTED) {
        throw new Error("Session not ready");
      }

      const messageId = crypto.randomUUID();
      const sessionMessage: SessionMessage = {
        type: "request",
        messageId,
        payload: message,
      };

      await sessionTransport.transport.send(sessionMessage);

      return awaitCorrelatedResponse(messages, messageId, ackTimeout, responseTimeout);
    },
    _internal: {
      signal,
      get transport() {
        return sessionTransport.transport;
      },
    },
    emitter,
  };
};

/** Connect to a session from its openlv:// URL. */
export const connectSession = async (
  connectionUrl: string,
  onMessage: (message: unknown) => Promise<unknown>,
  transports: TransportLayerFunction[],
  options?: SessionOptions,
): Promise<Session> => {
  const initParameters = decodeConnectionURL(connectionUrl);

  return createSession(initParameters, transports, onMessage, options);
};
