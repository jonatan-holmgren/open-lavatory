import { generateKeyPair } from "@openlv/core/encryption";
import { describe, expect, it } from "vitest";

import { Status } from "./index.js";
import type { SignalingChannel } from "./protocol.js";
import {
  createControlledChannel,
  createPairedPeer,
  createPeer,
  createSessionKeys,
  createTopic,
  establishFresh,
  PAIRING_ID,
  waitForState,
} from "./resume.fixtures.js";

const createFreshPair = async () => {
  const keys = await createSessionKeys();
  const hostChannel = createControlledChannel();
  const clientChannel = createControlledChannel();
  const { layer: host } = await createPairedPeer({ channel: hostChannel.channel, keys, isHost: true, initiate: false, isFresh: true });
  const { layer: client } = await createPairedPeer({ channel: clientChannel.channel, keys, isHost: false, initiate: false, isFresh: true });

  await host.setup();
  await client.setup();
  await hostChannel.receive(clientChannel.published[0]!);
  await clientChannel.receive(hostChannel.published[0]!);
  await hostChannel.receive(clientChannel.published[1]!);
  await clientChannel.receive(hostChannel.published[1]!);
  await hostChannel.receive(clientChannel.published[2]!);

  return { host, client, hostChannel, clientChannel, keys };
};

describe("signaling resume (in-memory relay)", () => {
  it("resumes sequential subscriptions when the first peer's request is lost", async () => {
    const topic = createTopic();
    const keys = await createSessionKeys();
    const host = await createPairedPeer({ channel: topic.channel(), keys: keys, isHost: true, initiate: true });
    const client = await createPairedPeer({ channel: topic.channel(), keys: keys, isHost: false, initiate: true });

    try {
      await host.layer.setup();
      await host.layer.resume();

      expect(host.layer.status.get()).not.toBe(Status.ENCRYPTED);

      await client.layer.setup();

      const encrypted = Promise.all([
        waitForState(host.layer, Status.ENCRYPTED),
        waitForState(client.layer, Status.ENCRYPTED),
      ]);

      await client.layer.resume();
      await encrypted;

      expect(host.layer.peerKey.get()?.toString()).toBe(keys.clientKeys.encryptionKey.toString());
      expect(client.layer.peerKey.get()?.toString()).toBe(keys.hostKeys.encryptionKey.toString());
    }
    finally {
      await Promise.all([host.layer.teardown(), client.layer.teardown()]);
    }
  });

  it("resumes when both peers restart", async () => {
    const topic = createTopic();
    const keys = await createSessionKeys();
    const first = await establishFresh(topic, keys);

    await Promise.all([first.host.layer.teardown(), first.client.layer.teardown()]);

    const host = await createPairedPeer({ channel: topic.channel(), keys: keys, isHost: true, initiate: true });
    const client = await createPairedPeer({ channel: topic.channel(), keys: keys, isHost: false, initiate: true });

    await Promise.all([host.layer.setup(), client.layer.setup()]);

    const encrypted = Promise.all([
      waitForState(host.layer, Status.ENCRYPTED),
      waitForState(client.layer, Status.ENCRYPTED),
    ]);

    await Promise.all([host.layer.resume(), client.layer.resume()]);
    await encrypted;

    expect(host.layer.peerKey.get()?.toString()).toBe(keys.clientKeys.encryptionKey.toString());
    expect(client.layer.peerKey.get()?.toString()).toBe(keys.hostKeys.encryptionKey.toString());

    await Promise.all([host.layer.teardown(), client.layer.teardown()]);
  });

  it("accepts a resume from a restarted host while the client stays connected", async () => {
    const topic = createTopic();
    const keys = await createSessionKeys();
    const first = await establishFresh(topic, keys);

    await first.host.layer.teardown();

    const clientResumed = new Promise<void>(resolve => first.client.layer.on("resume", resolve));
    const host = await createPairedPeer({ channel: topic.channel(), keys: keys, isHost: true, initiate: true });

    await host.layer.setup();

    const encrypted = Promise.all([
      waitForState(host.layer, Status.ENCRYPTED),
      clientResumed,
    ]);

    await host.layer.resume();
    await encrypted;

    expect(first.client.layer.status.get()).toBe(Status.ENCRYPTED);
    expect(first.client.layer.peerKey.get()?.toString()).toBe(keys.hostKeys.encryptionKey.toString());

    await Promise.all([host.layer.teardown(), first.client.layer.teardown()]);
  });

  it("accepts a resume from a restarted client while the host stays connected", async () => {
    const topic = createTopic();
    const keys = await createSessionKeys();
    const first = await establishFresh(topic, keys);

    await first.client.layer.teardown();

    const hostResumed = new Promise<void>(resolve => first.host.layer.on("resume", resolve));
    const client = await createPairedPeer({ channel: topic.channel(), keys: keys, isHost: false, initiate: true });

    await client.layer.setup();

    const encrypted = Promise.all([
      waitForState(client.layer, Status.ENCRYPTED),
      hostResumed,
    ]);

    await client.layer.resume();
    await encrypted;

    expect(first.host.layer.status.get()).toBe(Status.ENCRYPTED);
    expect(first.host.layer.peerKey.get()?.toString()).toBe(keys.clientKeys.encryptionKey.toString());

    await Promise.all([client.layer.teardown(), first.host.layer.teardown()]);
  });

  it("terminally rejects a replayed resume frame after reloading", async () => {
    const topic = createTopic();
    const responderKeys = await generateKeyPair();
    const initiatorKeys = await generateKeyPair();

    // Wrap both channels so a published frame can be captured and replayed,
    // exactly as a relay could, and so the responder's answers can be counted.
    const responderChannel = topic.channel();
    const responderPublished: string[] = [];
    const capturingResponderChannel: SignalingChannel = {
      ...responderChannel,
      publish: (payload) => {
        responderPublished.push(payload);
        responderChannel.publish(payload);
      },
    };
    const responder = await createPeer({
      channel: capturingResponderChannel,
      isHost: true,
      h: "unused",
      encryptionKey: responderKeys.encryptionKey,
      decryptionKey: responderKeys.decryptionKey,
      pinnedKey: initiatorKeys.encryptionKey,
      pairingId: PAIRING_ID,
      initiate: false,
    });

    const initiatorChannel = topic.channel();
    const initiatorPublished: string[] = [];
    const capturingInitiatorChannel: SignalingChannel = {
      ...initiatorChannel,
      publish: (payload) => {
        initiatorPublished.push(payload);
        initiatorChannel.publish(payload);
      },
    };
    const initiator = await createPeer({
      channel: capturingInitiatorChannel,
      isHost: false,
      h: "unused",
      encryptionKey: initiatorKeys.encryptionKey,
      decryptionKey: initiatorKeys.decryptionKey,
      pinnedKey: responderKeys.encryptionKey,
      pairingId: PAIRING_ID,
      initiate: true,
    });

    await Promise.all([responder.layer.setup(), initiator.layer.setup()]);

    const encrypted = Promise.all([
      waitForState(initiator.layer, Status.ENCRYPTED),
      waitForState(responder.layer, Status.ENCRYPTED),
    ]);

    await initiator.layer.resume();
    await encrypted;

    // The responder answered the resume exactly once.
    expect(responderPublished).toHaveLength(1);

    // Restarting the responder must preserve the high-water mark. A relay
    // replaying a frame captured before the restart cannot receive another ack.
    const replayed = initiatorPublished[0];

    expect(replayed).toBeDefined();
    await responder.layer.teardown();

    const reloadedChannel = topic.channel();
    const reloadedPublished: string[] = [];
    const capturingReloadedChannel: SignalingChannel = {
      ...reloadedChannel,
      publish: (payload) => {
        reloadedPublished.push(payload);
        reloadedChannel.publish(payload);
      },
    };
    const reloadedResponder = await createPeer({
      channel: capturingReloadedChannel,
      isHost: true,
      h: "unused",
      encryptionKey: responderKeys.encryptionKey,
      decryptionKey: responderKeys.decryptionKey,
      pinnedKey: initiatorKeys.encryptionKey,
      pairingId: PAIRING_ID,
      initiate: false,
      state: responder.resumeState,
    });

    await reloadedResponder.layer.setup();

    const failed = waitForState(reloadedResponder.layer, Status.ERROR);

    if (replayed) initiatorChannel.publish(replayed);

    await failed;

    expect(reloadedPublished).toHaveLength(0);
    expect(reloadedResponder.layer.peerKey.get()).toBeUndefined();
    await expect(reloadedResponder.layer.resume()).rejects.toThrow(/failed|error/i);
    await expect(reloadedResponder.layer.setup()).rejects.toThrow(/failed|error/i);
    await expect(reloadedResponder.layer.send({ message: "blocked" })).rejects.toThrow(/failed|error/i);

    await Promise.all([reloadedResponder.layer.teardown(), initiator.layer.teardown()]);
  });
});

it("an unpinned host accepts a second scan after the first scanner leaves", async () => {
  const keys = await createSessionKeys();
  const clientKeys = await generateKeyPair();
  const hostChannel = createControlledChannel();
  const firstChannel = createControlledChannel();
  const clientChannel = createControlledChannel();
  const { layer: host } = await createPairedPeer({ channel: hostChannel.channel, keys, isHost: true, initiate: false, isFresh: true });
  const { layer: first } = await createPairedPeer({ channel: firstChannel.channel, keys, isHost: false, initiate: false, isFresh: true });
  const { layer: client } = await createPairedPeer({ channel: clientChannel.channel, keys: { ...keys, clientKeys }, isHost: false, initiate: false, isFresh: true });
  const received: object[] = [];

  client.on("message", (message) => {
    received.push(message);
  });

  try {
    await host.setup();
    await first.setup();
    await hostChannel.receive(firstChannel.published[0]!);
    await first.teardown();
    hostChannel.published.pop();
    expect(host.peerKey.get()).toBeUndefined();
    await client.setup();

    while (hostChannel.published.length > 0 || clientChannel.published.length > 0) {
      for (const frame of clientChannel.published) await hostChannel.receive(frame);

      clientChannel.published.length = 0;

      for (const frame of hostChannel.published) await clientChannel.receive(frame);

      hostChannel.published.length = 0;
    }

    expect(host.status.get()).toBe(Status.ENCRYPTED);
    expect(client.status.get()).toBe(Status.ENCRYPTED);
    expect(host.peerKey.get()?.toString()).toBe(clientKeys.encryptionKey.toString());
    await host.send({ request: "rescanned" });
    await clientChannel.receive(hostChannel.published.at(-1)!);
    expect(received).toEqual([{ request: "rescanned" }]);
  }
  finally {
    await Promise.all([host.teardown(), first.teardown(), client.teardown()]);
  }
});

describe("bootstrap messages after pairing", () => {
  it("an old bootstrap URI cannot replace a learned peer pin", async () => {
    const { host, client, hostChannel, clientChannel, keys } = await createFreshPair();
    const attacker = await generateKeyPair();
    const received: object[] = [];

    client.on("message", (message) => {
      received.push(message);
    });

    try {
      await hostChannel.receive(clientChannel.published[0]!);
      const substitutedKey = JSON.stringify({
        type: "pubkey", payload: { publicKey: attacker.encryptionKey.toString() }, timestamp: Date.now(),
      });
      const capabilities = JSON.stringify({
        type: "capabilities", payload: { transports: ["wrtc"] }, timestamp: Date.now(),
      });

      await hostChannel.receive(`xh${await keys.hostKeys.encryptionKey.encrypt(substitutedKey)}`);
      await hostChannel.receive(`xh${await keys.hostKeys.encryptionKey.encrypt(capabilities)}`);

      expect(host.peerKey.get()?.toString()).toBe(keys.clientKeys.encryptionKey.toString());
      expect(host.status.get()).toBe(Status.ENCRYPTED);
      await host.send({ request: "still paired" });
      await clientChannel.receive(hostChannel.published.at(-1)!);
      expect(received).toEqual([{ request: "still paired" }]);
    }
    finally {
      await Promise.all([host.teardown(), client.teardown()]);
    }
  });

  it("duplicate bootstrap messages do not restart an established client", async () => {
    const { host, client, hostChannel, clientChannel, keys } = await createFreshPair();
    const states: string[] = [];

    client.status.subscribe((state) => {
      states.push(state);
    });

    try {
      await clientChannel.receive(hostChannel.published[0]!);
      await clientChannel.receive(hostChannel.published[1]!);

      expect(states).toEqual([Status.ENCRYPTED]);
      expect(client.peerKey.get()?.toString()).toBe(keys.hostKeys.encryptionKey.toString());
    }
    finally {
      await Promise.all([host.teardown(), client.teardown()]);
    }
  });

  it("a restored client cannot complete resume using recorded bootstrap traffic", async () => {
    const { host, client, hostChannel, keys } = await createFreshPair();
    const resumedChannel = createControlledChannel();
    const resumed = await createPairedPeer({ channel: resumedChannel.channel, keys, isHost: false, initiate: true });

    try {
      await resumed.layer.setup();
      await resumed.layer.resume();
      await resumedChannel.receive(hostChannel.published[0]!);
      await resumedChannel.receive(hostChannel.published[1]!);

      expect(resumed.layer.status.get()).toBe(Status.HANDSHAKE_PARTIAL);
      expect(resumed.layer.peerKey.get()).toBeUndefined();
      await expect(resumed.layer.send({ request: "must not send" })).rejects.toThrow();
    }
    finally {
      await Promise.all([host.teardown(), client.teardown(), resumed.layer.teardown()]);
    }
  });

  it("a pinned peer ignores capabilities frames after it has resumed", async () => {
    const topic = createTopic();
    const keys = await createSessionKeys();
    const host = await createPairedPeer({ channel: topic.channel(), keys, isHost: true, initiate: true });
    const clientChannel = topic.channel();
    const clientPublished: string[] = [];
    const capturingClientChannel: SignalingChannel = {
      ...clientChannel,
      publish: (payload) => {
        clientPublished.push(payload);
        clientChannel.publish(payload);
      },
    };
    const client = await createPairedPeer({ channel: capturingClientChannel, keys, isHost: false, initiate: true });

    try {
      await Promise.all([host.layer.setup(), client.layer.setup()]);

      const encrypted = Promise.all([
        waitForState(host.layer, Status.ENCRYPTED),
        waitForState(client.layer, Status.ENCRYPTED),
      ]);

      await Promise.all([host.layer.resume(), client.layer.resume()]);
      await encrypted;

      const publishedBefore = clientPublished.length;
      const capabilities = JSON.stringify({
        type: "capabilities", payload: { transports: ["wrtc"] }, timestamp: Date.now(),
      });

      clientChannel.publish(`xc${await keys.clientKeys.encryptionKey.encrypt(capabilities)}`);
      await new Promise<void>((resolve) => {
        setTimeout(resolve, 0);
      });

      expect(clientPublished).toHaveLength(publishedBefore);
      expect(client.layer.status.get()).toBe(Status.ENCRYPTED);
    }
    finally {
      await Promise.all([host.layer.teardown(), client.layer.teardown()]);
    }
  });
});
