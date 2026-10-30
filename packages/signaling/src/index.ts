import { make, type Observable, observable, type PeerCapabilities } from "@openlv/core";
import type { EncryptionKey, PeerChannels, SymmetricKey } from "@openlv/core/encryption";
import { EventEmitter } from "eventemitter3";

import { createHandshake, Status } from "./handshake.js";
import type { SignalingChannel } from "./protocol.js";

export { Status } from "./handshake.js";
export * from "./messages.js";
export * from "./protocol.js";

type Channels = PeerChannels;
export type SignalingHandshake = {
  peerKey: EncryptionKey;
  peerCapabilities: PeerCapabilities;
  transport: Channels["transport"];
  resumptionSecret: string;
};
export type SignalEventMap = {
  message: (message: object) => void;
  error: (reason: string, isPairingInvalidated?: boolean) => void;
  handshake: (result: SignalingHandshake, isRestart: boolean) => void;
};
export type SignalingHooks = {
  isHost: boolean;
  h: string;
  k: SymmetricKey;
  sessionId: string;
  secretKey: string;
  publicKey: EncryptionKey;
  expectedPeerKey?: EncryptionKey;
  capabilities: PeerCapabilities;
  resumptionSecret?: string;
};
export type SignalingContext = {
  type: string;
  send: (message: object) => Promise<void>;
  setup: () => Promise<void>;
  teardown: () => Promise<void>;
  status: Observable<Status>;
  peerKey: Observable<EncryptionKey | undefined>;
  peerCapabilities: Observable<PeerCapabilities | undefined>;
};
export type SignalingLayer = EventEmitter<SignalEventMap> & SignalingContext;
export type SignalingLayerFunction = (hooks: SignalingHooks) => Promise<SignalingLayer>;
export type CreateSignalingLayerFunction = (base: SignalingChannel) => SignalingLayerFunction;

export const createSignalingLayer: CreateSignalingLayerFunction = channel => async (hooks) => {
  const [status, setStatus] = observable<Status>(Status.STANDBY);
  const [peerKey, setPeerKey] = observable<EncryptionKey | undefined>(undefined);
  const [peerCapabilities, setPeerCapabilities] = observable<PeerCapabilities | undefined>(undefined);
  const emitter = new EventEmitter<SignalEventMap>();
  const exchange = await createHandshake(channel, hooks, {
    emitter,
    status,
    setStatus,
    setPeerKey,
    setPeerCapabilities,
  });

  const setup = async () => {
    if (exchange.isStopped) throw new Error("Signaling has been torn down");

    setStatus(Status.CONNECTING);
    await channel.setup();

    if (exchange.isStopped) return;

    await channel.subscribe(exchange.receive);

    if (exchange.isStopped) return;

    setStatus(Status.READY);
    exchange.startRetries();
    await exchange.start();
  };

  return make(emitter, {
    type: channel.type, setup,
    async teardown() {
      exchange.stop();
      await channel.teardown();
    },
    async send(payload: object) {
      await exchange.send(payload);
    },
    status, peerKey, peerCapabilities,
  });
};
