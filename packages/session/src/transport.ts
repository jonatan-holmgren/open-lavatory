import { type PeerCapabilities, SESSION_SETUP_TIMEOUT_MS } from "@openlv/core";
import type { SignalingLayer } from "@openlv/signaling";
import {
  Status as TransportStatus,
  type TransportLayer,
  type TransportLayerFunction,
  type TransportLayerParameters,
} from "@openlv/transport";

import type { SessionMessage } from "./messages/index.js";

export type SessionTransportOptions = {
  transportLayers: TransportLayerFunction[];
  capabilities: PeerCapabilities;
  signal: SignalingLayer;
  isHost: boolean;
  selectedTransportId?: string;
  encrypt: TransportLayerParameters["encrypt"];
  decrypt: TransportLayerParameters["decrypt"];
  onmessage: TransportLayerParameters["onmessage"];
  isStopped: () => boolean;
  isConnected: () => boolean;
  isResuming: boolean;
  flushNegotiation: () => Promise<void>;
  onConnected: () => void;
  onDisconnected: () => void;
  onError: (reason?: string) => void;
  onSetupError: (error: unknown, hasTransport: boolean) => void;
  onTimeout: (isResuming: boolean) => void;
};

export type SessionTransport = {
  readonly transport: TransportLayer | undefined;
  readonly selectedTransportId: string | undefined;
  readonly isReady: boolean;
  armLinkDeadline: () => void;
  start: (shouldRestart?: boolean) => Promise<void>;
  resume: () => void;
  teardown: () => Promise<void>;
};

export const createSessionTransport = (
  options: SessionTransportOptions,
): SessionTransport => {
  const {
    transportLayers,
    capabilities,
    signal,
    isHost,
    encrypt,
    decrypt,
    onmessage,
    isStopped,
    isConnected,
    isResuming,
    flushNegotiation,
    onConnected,
    onDisconnected,
    onError,
    onSetupError,
    onTimeout,
  } = options;
  let transport: TransportLayer | undefined;
  let selectedTransportId = options.selectedTransportId;
  let isReady = false;
  let linkDeadline: ReturnType<typeof setTimeout> | undefined;
  let unsubscribeStatus: (() => void) | undefined;
  let operation: Promise<void> = Promise.resolve();
  let teardownPromise: Promise<void> | undefined;

  const clearLinkDeadline = () => {
    clearTimeout(linkDeadline);
    linkDeadline = undefined;
  };

  const armLinkDeadline = () => {
    linkDeadline ??= setTimeout(() => {
      if (isConnected()) return;

      onTimeout(isResuming);
    }, SESSION_SETUP_TIMEOUT_MS);
  };

  const onTransportStateChange = (status: TransportStatus) => {
    if (isStopped()) return;

    if (status === TransportStatus.CONNECTED) {
      clearLinkDeadline();
      onConnected();
    }

    if (status === TransportStatus.ERROR) {
      clearLinkDeadline();
      onDisconnected();
    }
  };

  const start = (shouldRestart = false): Promise<void> => {
    const previous = operation;

    operation = (async () => {
      await previous;

      if (isStopped() || !signal.peerKey.get() || (!shouldRestart && transport)) return;

      try {
        let current = transport;

        if (current) {
          await current.teardown();

          if (isStopped()) return;
        }
        else {
          const peerCapabilities = signal.peerCapabilities.get();
          let transportId = selectedTransportId;

          if (!transportId && peerCapabilities) {
            const hostPreference = isHost ? capabilities.transports : peerCapabilities.transports;
            const clientSupported = isHost ? peerCapabilities.transports : capabilities.transports;

            transportId = hostPreference.find(candidate => clientSupported.includes(candidate));
          }

          const layer = transportLayers.find(layer => layer.transportId === transportId);

          if (!layer) throw new Error("No common transport with peer");

          selectedTransportId = layer.transportId;
          current = layer.create({
            encrypt,
            decrypt,
            isHost,
            onmessage,
            async subsend(message) {
              await signal.send({
                type: "request",
                messageId: crypto.randomUUID(),
                payload: message,
              } satisfies SessionMessage);
            },
          });
          transport = current;
          current.emitter.on("error", onError);
          unsubscribeStatus = current.status.subscribe(onTransportStateChange);
        }

        armLinkDeadline();
        await current.setup();

        if (isStopped()) return;

        isReady = true;
        await flushNegotiation();
      }
      catch (error) {
        clearLinkDeadline();
        onSetupError(error, transport !== undefined);
      }
    })();

    return operation;
  };

  const resume = () => {
    if (isStopped()) return;

    isReady = false;
    armLinkDeadline();
    void start(true);
  };

  const teardown = (): Promise<void> => {
    if (teardownPromise) return teardownPromise;

    clearLinkDeadline();
    unsubscribeStatus?.();
    unsubscribeStatus = undefined;
    const closingTransport = transport;

    transport = undefined;
    isReady = false;
    closingTransport?.emitter.off("error", onError);
    teardownPromise = (async () => {
      await operation;
      await closingTransport?.teardown();
    })();

    return teardownPromise;
  };

  return {
    get transport() {
      return transport;
    },
    get selectedTransportId() {
      return selectedTransportId;
    },
    get isReady() {
      return isReady;
    },
    armLinkDeadline,
    start,
    resume,
    teardown,
  };
};
