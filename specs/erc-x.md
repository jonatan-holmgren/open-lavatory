---
title: Open Lavatory Connectivity Protocol
description: A connectivity protocol for establishing wallet-dapp EIP-1193-compatible transport.
author: Luc van Kampen (@lucemans) <luc.van.kampen@ethereum.org>
discussions-to: TBD
status: Draft
type: Standards Track
category: ERC
created: 2026-04-29
requires: 1193
---

## Abstract

This specification defines `open-lavatory`, hereafter `openlv`, an Ethereum wallet-dapp wire protocol for session establishment and transport of EIP-1193 messages.
`openlv` standardizes a bootstrap URI, encrypted signaling frames, transport negotiation messages, a correlated session message envelope, and an authenticated session resumption model.
It builds upon the wallet pairing flow introduced by [ERC-1328](./eip-1328.md).

## Motivation

Ethereum wallet connectivity benefits from protocols that are portable, open, and easy for wallets and dapps to adopt without depending on a single service provider or control plane.
The ecosystem benefits when users and implementers can choose their own infrastructure, self-host when desired, and preserve compatibility across independent implementations.

`openlv` preserves the familiar wallet-pairing model while allowing wallets and dapps to exchange standard EIP-1193 messages over user-chosen signaling infrastructure and a direct peer transport.
It offers an open and interoperable approach to wallet connectivity while keeping the transport of Ethereum wallet messages straightforward.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### Overview

`openlv` operates in five steps:

1. An advertising peer creates a session URI.
2. That URI is transferred out-of-band to a joining peer.
3. Both peers use shared signaling infrastructure to exchange encrypted bootstrap messages and negotiate transport.
4. The peers establish a direct transport.
5. Application messages, such as EIP-1193 requests and responses, flow over the established transport.

Peers are asymmetric only during bootstrap and signaling.
After transport establishment, both parties are simply peers and may send requests and responses bidirectionally.

### Roles

- **Advertising peer**: the peer that creates and shares the session URI. In common deployments, the dapp.
- **Joining peer**: the peer that receives the session URI and joins the session. In common deployments, the wallet.

These roles apply only to bootstrap and signaling behavior.

### Protocol Phases

Version 1 has two communication layers.

- **Signaling layer**: used to bootstrap the session, exchange peer key material, and carry transport negotiation payloads.
- **Transport layer**: used after negotiation for ordinary application traffic.

The signaling layer exists only to establish secure peer communication.
After the transport layer is established, application messages, such as EIP-1193 requests, are carried in the session envelope described below.

### Session URI

The version 1 session URI format is:

```text
openlv://<sessionId>@1?h=<h>&k=<k>&p=<p>&s=<s>
```

All fields are REQUIRED for deterministic interoperability.

- `sessionId`: 16 URL-safe characters matching `^[A-Za-z0-9_-]{16}$`
- `h`: 16 lowercase hexadecimal characters matching `^[0-9a-f]{16}$`
- `k`: 32 lowercase hexadecimal characters matching `^[0-9a-f]{32}$`
- `p`: signaling protocol identifier, e.g. `mqtt` or `ntfy`
- `s`: URL-encoded signaling server URL

`sessionId` identifies the shared signaling namespace.

`p` and `s` identify how the peers reach the signaling infrastructure.
At the protocol level, `p` and `s` are REQUIRED.
Implementations MAY expose local defaults, but interoperable peers MUST NOT assume them.

`k` provides the shared symmetric key material used for the initial signaling stage before peer public keys have been exchanged.

`h` commits the URI to the advertising peer public key.
`h` is the first 16 characters of the lowercase hex encoding of the SHA-256 digest of the 32-byte X25519 public key.
The joining peer MUST compute `h` from the public key it receives in `pubkey`, and MUST abort the handshake if the result differs from the `h` in the URI.

In the current interoperable behavior, `k` is hex-decoded and imported as symmetric handshake key material.

### Signaling Infrastructure

Peers MUST connect to shared signaling infrastructure derived from `p` and `s`.
This signaling infrastructure is untrusted and is used only for encrypted signaling messages and transport negotiation payloads.

This specification does not mandate a single signaling protocol or a purpose-built openlv service.
A conforming signaling server MUST carry byte-equivalent text payloads between peers within a shared session.

This specification is designed to operate over general-purpose signaling services, including publicly available or self-hosted MQTT, NTFY, or similar systems, without requiring those services to implement protocol-specific logic or prior setup.

### Signaling Model

The signaling layer begins with messages encrypted under `k`.
Once the peers have exchanged public keys, signaling continues using peer public-key encryption.

Version 1 therefore uses two signaling encryption modes:

- handshake-key encryption for early bootstrap messages
- peer public-key encryption after public key exchange

### Signaling Frame Format

Each signaling frame is serialized as:

```text
<prefix><recipient><ciphertext>
```

- `prefix`: one ASCII character identifying the encryption mode
- `recipient`: one ASCII character identifying the intended role during signaling
- `ciphertext`: base64 text of the encrypted JSON payload

Version 1 defines:

- `h` as the handshake-key encrypted frame prefix
- `x` as the peer-key encrypted frame prefix
- `h` as the advertising-peer recipient marker
- `c` as the joining-peer recipient marker

In version 1, the character `h` is reused in two different positions: once as a frame prefix and once as a recipient marker.
These meanings are distinguished by position within the frame.

Receivers MUST ignore frames where `recipient` does not match the local role.

### Signaling Messages

After decryption, a signaling payload MUST be valid JSON containing:

- `type`: one of `flash`, `pubkey`, `capabilities`, `data`, `resume`, `resume-ack`, or `resume-confirm`
- `payload`: defined below based on `type`.
- `timestamp`: time in milliseconds since Unix epoch.

The signaling message types have the following meanings:

- `flash`: sent by the joining peer to begin the handshake
- `pubkey`: carries a peer public key
- `capabilities`: acknowledges the previous handshake step, negotiates the transport, and carries optional peer metadata
- `data`: carries post-handshake signaling payloads, including transport negotiation objects
- `resume`, `resume-ack`, `resume-confirm`: carry the authenticated resumption handshake described in Session Resumption

The `capabilities` payload is:

```json
{
  "transports": ["wrtc"],
  "info": {
    "identity": "com.example.wallet",
    "name": "Example Wallet",
    "icon": "data:image/png;base64,..."
  }
}
```

- `transports`: REQUIRED, a non-empty array of transport identifiers in preference order. Version 1 defines `wrtc` (WebRTC) and reserves `ws` (relayed WebSocket). Receivers MUST skip unknown identifiers rather than reject the message.
- `info`: OPTIONAL self-description shown in the other peer's UI. When present, `identity` (a reverse-DNS application identifier) and `name` are REQUIRED; `icon` is OPTIONAL and MAY be a data URI or an image URL. 
 
Receivers MUST treat `info` as untrusted display data: an implementation that renders or fetches `icon` is responsible for validating it first.

Relays cap message size, so `icon` SHOULD NOT exceed 8192 characters, a limit that testing with common relays showed to be safe, and implementations SHOULD apply sane limits to the other fields.

The resumption payloads are:

```json
{
  "version": 1,
  "pairingId": "<pairing id>",
  "publicKey": "<sender static public key>",
  "challenge": "<fresh challenge>",
  "counter": 42
}
```

```json
{
  "version": 1,
  "pairingId": "<pairing id>",
  "publicKey": "<sender static public key>",
  "challenge": "<fresh challenge>",
  "initiatorChallenge": "<echo of the initiator challenge>",
  "counter": 7
}
```

```json
{
  "pairingId": "<pairing id>",
  "proof": "<proof over the resume transcript>"
}
```

Every field in the `resume` and `resume-ack` payloads is REQUIRED.
`counter` MUST be a non-negative safe integer; receivers MUST reject non-integers and negative values.
`pairingId`, the serialized public keys, and the challenges MUST be bounded strings; receivers MUST reject empty or oversized values.
`proof` is a lowercase hexadecimal string.

### Handshake Sequence

The version 1 handshake sequence is:

1. The joining peer sends `flash` to the advertising peer using a handshake-key encrypted frame.
2. The advertising peer sends `pubkey` to the joining peer using a handshake-key encrypted frame.
3. The joining peer records the advertising peer public key and sends `pubkey` using a peer public-key encrypted frame.
4. The advertising peer records the joining peer public key and sends `capabilities` using a peer public-key encrypted frame. This message doubles as the delivery receipt for the joining peer's `pubkey`.
5. The joining peer records the advertising peer capabilities and sends `capabilities` using a peer public-key encrypted frame. This message doubles as the delivery receipt for the advertising peer's `capabilities`.
6. Both peers treat subsequent signaling data as peer public-key encrypted.

Signaling infrastructure is lossy, so each handshake step MAY be re-sent until the next inbound message confirms progress; receivers MUST treat duplicate deliveries as no-ops. A joining peer that continues to receive `capabilities` after completing the handshake MUST answer each duplicate, since its own final message may have been lost.

After the handshake, signaling application payloads MUST be carried in `data` messages inside peer public-key encrypted frames.

### Transport Selection

Both `transports` lists are preference-ordered. The selected transport is the first entry in the advertising peer's list that also appears in the joining peer's list. Both peers compute this independently once they hold both lists; no additional confirmation message is exchanged. If the intersection is empty, the session MUST fail with a no-common-transport error.

### Transport Negotiation

After the handshake selects a transport, peers negotiate the direct connection through the signaling layer.
These negotiation objects are carried over signaling before the direct transport exists.
The shape of negotiation payloads is owned by the selected transport; receivers MUST ignore unknown negotiation message types.

For the `wrtc` transport, version 1 standardizes carriage of WebRTC negotiation payloads as signaling `data` messages whose payload is one of:

```json
{ "type": "offer", "payload": "<sdp-json-string>" }
```

```json
{ "type": "answer", "payload": "<sdp-json-string>" }
```

```json
{ "type": "candidate", "payload": "<candidate-json-string>" }
```

The advertising peer sends the `offer` with its available transports, the joining peer replies with a decisive `answer`.

When a protocol has negotiated a transport, both peers send `candidate` messages as they discover them.

### Session Envelope

Once transport is established, peers exchange session messages over it.
A session message is a JSON object with a string member `type`.
Version 1 defines the types `request`, `ack`, `response`, and `close`.

A receiver MUST ignore a session message whose `type` it does not recognise.

The `payload` member of a session message is an opaque JSON value.
The session layer MUST NOT inspect or modify `payload`.
The application that uses the session defines what `payload` contains.
For EIP-1193 traffic, each `payload` is an EIP-1193 request or response, carried unchanged.

The examples in this section carry EIP-1193 payloads.
These payloads only illustrate the envelope, and any JSON value can take their place.

Either peer MAY send a `request`.
A `request` carries a `messageId` and a `payload`:

```json
{ "type": "request", "messageId": "5b0e6f3c...", "payload": { "jsonrpc": "2.0", "id": 1, "method": "eth_requestAccounts" } }
```

`messageId` is a string.
It MUST be unique among the requests that its sender sends in the session.
Implementations SHOULD use a random UUID.

The receiver SHOULD send `ack` as soon as it receives a `request`, before any user interaction:

```json
{ "type": "ack", "messageId": "5b0e6f3c..." }
```

The receiver MUST send exactly one `response` for each `request`, with the same `messageId`:

```json
{ "type": "response", "messageId": "5b0e6f3c...", "payload": { "jsonrpc": "2.0", "id": 1, "result": ["0x1234567890abcdef1234567890abcdef12345678"] } }
```

A sender MUST accept a `response` that arrives without a prior `ack`.
A sender MUST ignore an `ack` or `response` whose `messageId` does not match one of its open requests.
A sender SHOULD fail a request that receives no `ack` within a bounded interval.
The `ack` separates a lost message from a slow user, so a sender SHOULD NOT apply a short deadline after the `ack` arrives.

Either peer MAY end the session by sending `{ "type": "close" }` before it closes the transport.
A `close` has no `messageId` and is not acknowledged.
After a peer sends or receives `close`, it MUST NOT send further session messages and MUST fail its open requests.

### Session Resumption

Peers MAY persist state locally to resume a pairing after one or both sides restart.
Persisted state includes the session configuration (`sessionId`, `p`, `s`, `k`), the local X25519 keypair, the pinned peer public key, the negotiated transport identifier, a `pairingId` stable for the lifetime of the pairing, and the replay counters described below.
In version 1, `pairingId` is the `sessionId` from the original bootstrap URI.
The local keypair and the pinned peer key are stored serialized; the local storage backend is implementation-specific.

A session started from persisted state that carries a `pairingId` resumes instead of running the fresh handshake.
Resumption does not guarantee transport continuity: the peers reconnect to the signaling infrastructure and renegotiate the transport.
Resumed peers reuse the persisted transport identifier without exchanging capabilities again; transport negotiation rebuilds the underlying connection, not the transport selection.

Resumption is a three-message handshake carried in peer-key encrypted signaling frames:

1. The initiator sends `resume` to the responder's pinned public key. It carries the `pairingId`, the initiator's static public key, a fresh `challenge`, and an advanced `counter`.
2. The responder verifies the `pairingId`, that the advertised public key equals the pinned peer key, and that the `counter` advanced. It then replies with `resume-ack`, carrying its own static public key, a fresh `challenge`, an echo of the initiator's challenge in `initiatorChallenge`, and its advanced `counter`.
3. The initiator verifies the `pairingId`, the pinned public key, the `counter`, and the echoed challenge, then sends `resume-confirm` carrying a `proof`.

`proof` is the lowercase hex encoding of `SHA-256(pairingId | initiatorPublicKey | responderPublicKey | initiatorChallenge | responderChallenge | initiatorCounter | responderCounter)`, where the parts are joined with `|`.
The responder's fresh `challenge` is delivered only inside the peer-key encrypted `resume-ack`, so only a holder of the pinned private key can compute a `proof` the responder accepts.
The responder MUST NOT accept a resume before verifying `resume-confirm`.

Implementations MUST ignore a resume whose `pairingId` or advertised public key does not match, whose `counter` is not strictly greater than the highest counter already seen, whose `initiatorChallenge` does not match, or whose `proof` is invalid.
On any such failure the peer MUST fail closed and require re-pairing through a fresh out-of-band `openlv://` URI.
Implementations MUST persist each counter high-water update before publishing the corresponding resumption frame. A failed write MUST abort resumption rather than send with an unpersisted counter.
Resumption MUST have a bounded deadline. Authentication failure or deadline expiry ends the session, invalidates saved pairing state, and requires a fresh bootstrap URI; it MUST NOT silently fall back to the fresh handshake on the failed pairing.

### Cryptography

`openlv` uses a two-stage encryption model during session establishment.

The initial signaling stage uses the pre-shared key `k` from the session URI.
This key is used only before peers have exchanged public keys, and allows the first bootstrap messages to be encrypted over untrusted signaling infrastructure.
For current interoperability, the 32-character hexadecimal `k` value is hex-decoded to 16 bytes and imported as an AES-GCM key.

Handshake encryption uses the Web Crypto API AES-GCM implementation with a fresh 12-byte random IV per message.
The serialized encrypted payload is:

```text
base64(iv || ciphertext)
```

After public keys are exchanged, signaling switches to peer public-key encryption.
Each peer generates an asymmetric encryption keypair and encrypts to the other peer's public key.
In the current implementation, this mechanism uses X25519 key agreement (`@noble/curves`) and XSalsa20-Poly1305 authenticated encryption (`@noble/ciphers`), with an ephemeral sender key for each encrypted message.

Peer-encrypted payloads are serialized as:

```text
base64(ephemeralPublicKey || nonce || ciphertext)
```

This same peer-key mechanism is also used to protect payloads exchanged through the negotiated transport layer.
Session resumption reuses it: resume frames are encrypted to the peers' pinned static public keys, and version 1 does not perform a fresh key agreement for resumed sessions.

These cryptographic mechanisms define the current interoperable behavior, but future revisions MAY define alternative suites or explicit cryptographic negotiation.

## Rationale

The protocol uses an out-of-band URI because it is easy to transfer, inspect, and encode in both desktop and mobile wallet flows.
It uses signaling infrastructure only for bootstrap and negotiation so ordinary wallet-dapp traffic does not remain dependent on intermediary servers after session establishment.
It carries EIP-1193 messages unchanged to preserve compatibility with existing Ethereum wallet and dapp interfaces.

The specification requires explicit `p` and `s` fields so interoperability does not depend on hidden assumptions about a default signaling service.

The peer model is intentionally asymmetric only during bootstrap and signaling.
Once a transport is established, both peers operate symmetrically and may initiate request/response traffic.

The signaling design is intentionally compatible with general-purpose messaging systems.
This reduces adoption overhead because implementations may use existing public services or deploy their own signaling servers without requiring openlv-specific infrastructure.

## Backwards Compatibility

This is a new protocol and does not change existing EIP-1193 semantics.
Wallets and dapps that do not implement `openlv` remain unaffected.

Version 1 compatibility depends on the `openlv://` URI shape, URI version `@1`, the `sessionId`/`h`/`k` constraints, signaling frame markers, signaling message types, and the session envelope.

## Reference Implementation

An initial implementation is available under the `@openlv/connector`, `@openlv/session`, and `@openlv/transport` packages on npm.

### dApp Implementation

```typescript
import { openlv } from "@openlv/connector";
import { createConfig, http } from "wagmi";
import { mainnet } from "wagmi/chains";

export const wagmiConfig = createConfig({
  chains: [mainnet],
  connectors: [openlv()],
  transports: {
    [mainnet.id]: http(),
  },
});
```

### Wallet Implementation

```typescript
import { connectSession } from "@openlv/session";
import { webrtc } from "@openlv/transport/webrtc";

const session = await connectSession(
  "openlv://...",
  async (message) => {
    return { result: "ok" };
  },
  [webrtc()],
);
```

## Security Considerations

The session URI contains sensitive bootstrap material and MUST be handled as a secret until the handshake completes.

Session establishment is first-come-first-serve; a shoulder-surfing attacker could frontrun QR code scanning but not man-in-the-middle; this would immediately be noticable to the user as their device would fail to connect.

An attacker who can replace the URI shown is assumed to already have control over the dApp and is therefore out of scope of this specification.

Implementations MUST use fresh randomness for IVs, nonces, ephemeral keys, and generated session identifiers.

Signaling infrastructure is untrusted and can observe metadata such as timing, size, and namespace.
Implementations SHOULD validate decrypted JSON structure and expected message types before acting on payloads.
Implementations SHOULD apply request timeouts and resource limits.

Resumption MUST use the monotonic per-pairing `counter` for replay protection, and peers MUST reject a resume whose counter does not strictly advance.
Because resumed sessions reuse the handshake's peer-key encryption to the pinned static keys rather than a fresh key agreement, version 1 resumption does not provide forward secrecy.
A failed `pairingId`, pin, counter, challenge, or `proof` check MUST fail closed and require re-pairing through a fresh out-of-band `openlv://` URI.

Persisted session state is sensitive. Browser implementations MAY use localStorage, where scripts running on the same origin can access the serialized private keys.
Implementations SHOULD allow users to disconnect and delete saved session state.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
