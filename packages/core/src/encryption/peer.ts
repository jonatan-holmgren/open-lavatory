import { bytesToHex, hexToBytes } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";

import { fromBase64, toBase64 } from "./base64.js";

export type PeerKeyParameters = {
  sessionId: string;
  version: number;
  role: "host" | "client";
  localSecretKey: string;
  hostPublicKey: string;
  clientPublicKey: string;
  /** The invitation PSK (16 bytes) or the saved resumption secret (32 bytes). */
  psk: string;
};

export type PeerChannelParameters = PeerKeyParameters & {
  hostNonce: string;
  clientNonce: string;
};

export type AuthenticatedChannel = {
  encrypt: (message: string, header?: string) => Promise<string>;
  decrypt: (ciphertext: string, header?: string) => Promise<string>;
};

export type PeerChannels = {
  signaling: { send: AuthenticatedChannel; receive: AuthenticatedChannel; };
  transport: { send: AuthenticatedChannel; receive: AuthenticatedChannel; };
  resumptionSecret: string;
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const WINDOW = 256n;
const MASK = (1n << WINDOW) - 1n;

const decodeHex = (value: string, lengths: number[]): Uint8Array<ArrayBuffer> => {
  if (!/^(?:[0-9a-f]{2})+$/i.test(value) || !lengths.includes(value.length / 2)) {
    throw new Error("Invalid key or nonce encoding");
  }

  return Uint8Array.from(hexToBytes(value));
};

const keyMaterial = (parameters: PeerKeyParameters) => {
  const secret = fromBase64(parameters.localSecretKey);
  const host = fromBase64(parameters.hostPublicKey);
  const client = fromBase64(parameters.clientPublicKey);
  const psk = decodeHex(parameters.psk, [16, 32]);

  if ((parameters.role !== "host" && parameters.role !== "client")
    || secret.length !== 32 || host.length !== 32 || client.length !== 32
    || toBase64(host) === toBase64(client)
    || toBase64(host) !== parameters.hostPublicKey || toBase64(client) !== parameters.clientPublicKey
    || toBase64(secret) !== parameters.localSecretKey) {
    throw new Error("Invalid X25519 key encoding");
  }

  const ownPublic = parameters.role === "host" ? host : client;

  if (toBase64(x25519.getPublicKey(secret)) !== toBase64(ownPublic)) {
    throw new Error("Local secret does not match public key");
  }

  const peerPublic = parameters.role === "host" ? client : host;

  // Noble rejects low-order points and the all-zero shared secret.
  const shared = x25519.getSharedSecret(secret, peerPublic);
  const ikm = new Uint8Array(shared.length + psk.length);

  ikm.set(shared);
  ikm.set(psk, shared.length);

  return { ikm, psk };
};

const context = (parameters: PeerKeyParameters, purpose: string, nonces?: [string, string]) =>
  encoder.encode(JSON.stringify([
    "openlv peer keys", parameters.version, parameters.sessionId,
    "host", parameters.hostPublicKey, "client", parameters.clientPublicKey,
    purpose, ...(nonces ?? []),
  ]));

const hkdf = async (ikm: Uint8Array<ArrayBuffer>, info: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> => {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);

  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info }, key, 256));
};

/** Stable for the original invitation and pinned static key pair; static DH does not provide forward secrecy. */
export const deriveResumptionSecret = async (parameters: PeerKeyParameters): Promise<string> => {
  const { ikm, psk } = keyMaterial(parameters);

  return bytesToHex(psk.length === 32 ? psk : await hkdf(ikm, context(parameters, "resumption")));
};

const channel = async (rawKey: Uint8Array<ArrayBuffer>): Promise<AuthenticatedChannel> => {
  const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt", "decrypt"]);
  let nextCounter = 0n;
  let highest = -1n;
  let received = 0n;
  const hasSeen = (counter: bigint) => highest >= counter
    && (highest - counter >= WINDOW || (received & (1n << (highest - counter))) !== 0n);

  return {
    encrypt: async (message, header = "") => {
      if (nextCounter > 0xFF_FF_FF_FF_FF_FF_FF_FFn) throw new Error("Channel counter exhausted");

      const nonce = new Uint8Array(12);

      new DataView(nonce.buffer).setBigUint64(4, nextCounter++);
      const encrypted = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: encoder.encode(header) }, key, encoder.encode(message),
      ));
      const payload = new Uint8Array(nonce.length + encrypted.length);

      payload.set(nonce);
      payload.set(encrypted, nonce.length);

      return toBase64(payload);
    },
    decrypt: async (payload, header = "") => {
      const bytes = fromBase64(payload);

      if (bytes.length < 28 || bytes[0] !== 0 || bytes[1] !== 0 || bytes[2] !== 0 || bytes[3] !== 0) {
        throw new Error("Invalid channel payload");
      }

      const counter = new DataView(bytes.buffer, bytes.byteOffset, 12).getBigUint64(4);

      if (hasSeen(counter)) throw new Error("Replayed channel payload");

      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: bytes.subarray(0, 12), additionalData: encoder.encode(header) }, key, bytes.subarray(12),
      );

      // Check again after the asynchronous authentication to reject concurrent duplicates.
      if (hasSeen(counter)) throw new Error("Replayed channel payload");

      if (counter > highest) {
        const shift = counter - highest;

        received = shift >= WINDOW ? 1n : ((received << shift) | 1n) & MASK;
        highest = counter;
      }
      else received |= 1n << (highest - counter);

      return decoder.decode(plain);
    },
  };
};

/** Derive purpose- and direction-specific keys bound to both fresh handshake nonces. */
export const derivePeerChannels = async (parameters: PeerChannelParameters): Promise<PeerChannels> => {
  decodeHex(parameters.hostNonce, [16]);
  decodeHex(parameters.clientNonce, [16]);
  const { ikm } = keyMaterial(parameters);
  const nonces: [string, string] = [parameters.hostNonce.toLowerCase(), parameters.clientNonce.toLowerCase()];
  const make = async (purpose: string, direction: string) => channel(await hkdf(ikm, context(parameters, `${purpose}:${direction}`, nonces)));
  const [hostSignal, clientSignal, hostTransport, clientTransport, resumptionSecret] = await Promise.all([
    make("signaling", "host-to-client"), make("signaling", "client-to-host"),
    make("transport", "host-to-client"), make("transport", "client-to-host"),
    deriveResumptionSecret(parameters),
  ]);
  const isHost = parameters.role === "host";

  return {
    signaling: { send: isHost ? hostSignal : clientSignal, receive: isHost ? clientSignal : hostSignal },
    transport: { send: isHost ? hostTransport : clientTransport, receive: isHost ? clientTransport : hostTransport },
    resumptionSecret,
  };
};
