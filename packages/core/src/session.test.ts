import { describe, expect, it } from "vitest";

import { type EncKeypair, generateKeyPair, hashPublicKey } from "./encryption/index.js";
import {
  parseSessionConnectionParameters,
  type SerializedEncryptionKey,
  type SessionConnectionParameters,
  validateSessionConnectionKeys,
} from "./session.js";

const createParameters = async (): Promise<{
  parameters: SessionConnectionParameters;
  local: EncKeypair;
  peer: EncKeypair;
}> => {
  const local = await generateKeyPair();
  const peer = await generateKeyPair();

  return {
    local,
    peer,
    parameters: {
      version: 1,
      sessionId: "mytestsession111",
      h: await hashPublicKey(local.encryptionKey),
      k: "0".repeat(32),
      p: "ntfy",
      s: "https://ntfy.sh/",
      relyingPublicKey: peer.encryptionKey.toString() as SerializedEncryptionKey,
      encryptionKey: local.encryptionKey.toString() as SerializedEncryptionKey,
      decryptionKey: local.decryptionKey.toString() as SerializedEncryptionKey,
      pairingId: "pairing-id",
      transportId: "wrtc",
      lastCounter: 1,
      lastSeenCounter: 2,
      lastSeenAckCounter: 3,
    },
  };
};

describe("session connection parameters", () => {
  it("parses a complete, well-formed saved session", async () => {
    const { parameters } = await createParameters();

    expect(parseSessionConnectionParameters(parameters)).toEqual(parameters);
  });

  it("rejects malformed protocol fields instead of treating them as opaque strings", async () => {
    const { parameters } = await createParameters();

    expect(parseSessionConnectionParameters({ ...parameters, sessionId: "short" })).toBeUndefined();
    expect(parseSessionConnectionParameters({ ...parameters, h: "hash" })).toBeUndefined();
    expect(parseSessionConnectionParameters({ ...parameters, k: "key" })).toBeUndefined();
    expect(parseSessionConnectionParameters({ ...parameters, encryptionKey: "own-public-key" })).toBeUndefined();
    expect(parseSessionConnectionParameters({ ...parameters, pairingId: "x".repeat(65) })).toBeUndefined();
    expect(parseSessionConnectionParameters({ ...parameters, transportId: "x".repeat(33) })).toBeUndefined();
  });

  it("accepts a hash that commits to the pinned peer key", async () => {
    const { parameters, peer } = await createParameters();

    await expect(validateSessionConnectionKeys({
      ...parameters,
      h: await hashPublicKey(peer.encryptionKey),
    })).resolves.toBe(true);
  });

  it("rejects a keypair whose secret does not match its public key", async () => {
    const { parameters, peer } = await createParameters();

    await expect(validateSessionConnectionKeys({
      ...parameters,
      decryptionKey: peer.decryptionKey.toString() as SerializedEncryptionKey,
    })).resolves.toBe(false);
  });

  it.each([
    ["zero", new Uint8Array(32)],
    ["nonzero low-order", Uint8Array.of(1, ...new Uint8Array(31))],
  ])("rejects a %s pinned peer key before restoring the session", async (_label, publicKey) => {
    const { parameters } = await createParameters();
    const relyingPublicKey = btoa(String.fromCodePoint(...publicKey)) as SerializedEncryptionKey;
    const parsed = parseSessionConnectionParameters({ ...parameters, relyingPublicKey });

    expect(parsed).toBeDefined();
    await expect(validateSessionConnectionKeys(parsed!)).resolves.toBe(false);
  });

  it("rejects a hash that commits to neither side of the pairing", async () => {
    const { parameters } = await createParameters();
    const unrelated = await generateKeyPair();

    await expect(validateSessionConnectionKeys({
      ...parameters,
      h: await hashPublicKey(unrelated.encryptionKey),
    })).resolves.toBe(false);
  });
});
