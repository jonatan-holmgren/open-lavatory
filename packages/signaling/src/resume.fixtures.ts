import type { DecryptionKey, EncKeypair, EncryptionKey } from "@openlv/core/encryption";
import { deriveSymmetricKey, generateKeyPair, hashPublicKey } from "@openlv/core/encryption";

import type { SignalingLayer, SignalingResumeState } from "./index.js";
import { createSignalingLayer, Status } from "./index.js";
import type { SignalMessage } from "./messages.js";
import { parseSignalMessage } from "./messages.js";
import type { SignalingChannel } from "./protocol.js";
const K = "00112233445566778899aabbccddeeff";
const PAIRING_ID = "pairingresume001";

type TestTopic = { channel: () => SignalingChannel; };
type SessionKeys = { hostKeys: EncKeypair; clientKeys: EncKeypair; h: string; };
type ControlledChannel = {
  channel: SignalingChannel;
  published: string[];
  receive: (payload: string) => Promise<void>;
};

/**
 * In-memory topic emulating a public relay: every publish is delivered to all
 * subscribers on a microtask.
 */
const createTopic = (): TestTopic => {
  const subscribers = new Set<(payload: string) => void>();

  return {
    channel(): SignalingChannel {
      let handler: ((payload: string) => void) | undefined;

      return {
        type: "memory",
        setup: () => {},
        teardown: () => {
          if (handler) subscribers.delete(handler);
        },
        publish: (payload: string) => {
          queueMicrotask(() => {
            for (const subscriber of subscribers) subscriber(payload);
          });
        },
        subscribe: (next) => {
          handler = next;
          subscribers.add(next);
        },
      };
    },
  };
};

type PeerParameters = {
  channel: SignalingChannel;
  isHost: boolean;
  h: string;
  encryptionKey: EncryptionKey;
  decryptionKey: DecryptionKey;
  pinnedKey: EncryptionKey;
  pairingId: string;
  initiate: boolean;
  state?: SignalingResumeState;
  persist?: (state: SignalingResumeState) => void;
  isFresh?: boolean;
};

const createPeer = async (parameters: PeerParameters) => {
  let peerKey: EncryptionKey | undefined;
  const resumeState = parameters.state ?? {
    pairingId: parameters.pairingId,
    lastCounter: 0,
    lastSeenCounter: 0,
    lastSeenAckCounter: 0,
  };

  const layer = await createSignalingLayer(parameters.channel)({
    isHost: parameters.isHost,
    h: parameters.h,
    k: await deriveSymmetricKey(K),
    publicKey: parameters.encryptionKey,
    canEncrypt: () => peerKey !== undefined,
    encrypt: (message) => {
      const key = peerKey ?? parameters.pinnedKey;

      return key.encrypt(message);
    },
    decrypt: message => parameters.decryptionKey.decrypt(message),
    capabilities: { transports: ["wrtc"] },
    expectedPeerKey: parameters.isFresh ? undefined : parameters.pinnedKey,
    resume: {
      ...resumeState,
      initiate: parameters.initiate,
      persist: (state) => {
        parameters.persist?.(state);
        Object.assign(resumeState, state);
      },
    },
  });

  layer.peerKey.subscribe((key) => {
    peerKey = key;
  });

  return { layer, resumeState };
};

const waitForState = (layer: SignalingLayer, target: string) =>
  new Promise<void>((resolve, reject) => {
    if (layer.status.get() === target) return resolve();

    layer.status.subscribe((state) => {
      if (state === target) resolve();

      if (state === Status.ERROR && target !== Status.ERROR) {
        // eslint-disable-next-line unicorn/no-multiple-promise-resolver-calls
        reject(new Error("signaling errored"));
      }
    });
  });

const createSessionKeys = async (): Promise<SessionKeys> => {
  const hostKeys = await generateKeyPair();
  const clientKeys = await generateKeyPair();

  return {
    hostKeys,
    clientKeys,
    h: await hashPublicKey(hostKeys.encryptionKey),
  };
};

const establishFresh = async (
  topic: TestTopic,
  keys: SessionKeys,
) => {
  const host = await createPairedPeer({
    channel: topic.channel(), keys, isHost: true, initiate: false, isFresh: true,
  });
  const client = await createPairedPeer({
    channel: topic.channel(), keys, isHost: false, initiate: false, isFresh: true,
  });

  await host.layer.setup();

  const encrypted = Promise.all([
    waitForState(host.layer, Status.ENCRYPTED),
    waitForState(client.layer, Status.ENCRYPTED),
  ]);

  await client.layer.setup();
  await encrypted;

  return { host, client };
};

const createPairedPeer = ({
  channel, keys, isHost, initiate, persist, isFresh,
}: Pick<PeerParameters, "channel" | "isHost" | "initiate" | "persist" | "isFresh"> & {
  keys: SessionKeys;
}) => {
  const local = isHost ? keys.hostKeys : keys.clientKeys;
  const peer = isHost ? keys.clientKeys : keys.hostKeys;

  return createPeer({
    channel,
    isHost,
    h: keys.h,
    encryptionKey: local.encryptionKey,
    decryptionKey: local.decryptionKey,
    pinnedKey: peer.encryptionKey,
    pairingId: PAIRING_ID,
    initiate,
    persist,
    isFresh,
  });
};

const createControlledChannel = (): ControlledChannel => {
  const published: string[] = [];
  let handler: ((payload: string) => void) | undefined;

  return {
    published,
    channel: {
      type: "memory",
      setup: () => {},
      teardown: () => {
        handler = undefined;
      },
      subscribe: (next) => {
        handler = next;
      },
      publish: (payload) => {
        published.push(payload);
      },
    },
    receive: async (payload) => {
      await handler?.(payload);
    },
  };
};

const createControlledPeers = async (persistence: {
  host?: (state: SignalingResumeState) => void;
  client?: (state: SignalingResumeState) => void;
} = {}) => {
  const keys = await createSessionKeys();
  const hostChannel = createControlledChannel();
  const clientChannel = createControlledChannel();
  const host = await createPairedPeer({ channel: hostChannel.channel, keys: keys, isHost: true, initiate: true, persist: persistence.host });
  const client = await createPairedPeer({ channel: clientChannel.channel, keys: keys, isHost: false, initiate: true, persist: persistence.client });

  await Promise.all([host.layer.setup(), client.layer.setup()]);

  return { keys, hostChannel, clientChannel, host, client };
};

const createAttackerPeers = async (advertisedKey: "pinned-key" | "different-key") => {
  const keys = await createSessionKeys();
  const attackerKeys = await generateKeyPair();
  const responderChannel = createControlledChannel();
  const attackerChannel = createControlledChannel();
  const responder = await createPairedPeer({
    channel: responderChannel.channel, keys, isHost: true, initiate: false,
  });
  const attacker = await createPeer({
    channel: attackerChannel.channel,
    isHost: false,
    h: keys.h,
    encryptionKey: advertisedKey === "pinned-key" ? keys.clientKeys.encryptionKey : attackerKeys.encryptionKey,
    decryptionKey: attackerKeys.decryptionKey,
    pinnedKey: keys.hostKeys.encryptionKey,
    pairingId: PAIRING_ID,
    initiate: true,
  });

  await Promise.all([responder.layer.setup(), attacker.layer.setup()]);

  return { responder, attacker, responderChannel, attackerChannel };
};

const readEncryptedFrame = async (payload: string, key: DecryptionKey): Promise<SignalMessage> => {
  const message = parseSignalMessage(await key.decrypt(payload.slice(2)));

  if (!message) throw new Error("Expected a valid signaling frame");

  return message;
};

export {
  createAttackerPeers,
  createControlledChannel,
  createControlledPeers,
  createPairedPeer,
  createPeer,
  createSessionKeys,
  createTopic,
  establishFresh,
  PAIRING_ID,
  readEncryptedFrame,
  waitForState,
};
