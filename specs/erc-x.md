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

This specification defines `open-lavatory`, hereafter `openlv`, an Ethereum wallet-dapp connectivity protocol for session establishment and transport of EIP-1193 messages.
`openlv` standardizes a bootstrap URI, encrypted signaling frames, transport negotiation messages, a correlated session message envelope, and an optional session resumption model.
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

`h` is the first 16 lowercase hex characters of the SHA-256 digest of the advertising peer's 32-byte X25519 public key.
The joining peer MUST compute `h` from the public key it receives in `pubkey`, and MUST abort the handshake if the result differs from the `h` in the URI.

In the current interoperable behavior, `k` is hex-decoded and imported as symmetric handshake key material.

### Signaling Infrastructure

Peers MUST connect to shared signaling infrastructure derived from `p` and `s`.
This signaling infrastructure is untrusted and is used only for encrypted signaling messages and transport negotiation payloads.

This specification does not mandate a single signaling protocol or a purpose-built openlv service.
A conforming signaling server MUST carry byte-equivalent text payloads between peers within a shared session.

This specification is designed to operate over general-purpose signaling services, including publicly available or self-hosted MQTT, NTFY, or similar systems, without requiring those services to implement protocol-specific logic or prior setup.

### Signaling Model

The signaling layer begins with messages encrypted under the invitation key `k`. Peers derive directional session keys from their X25519 static key agreement, the bootstrap secret, both public keys, the session ID, roles, and fresh nonces from both peers. Subsequent signaling and transport traffic uses these peer-bound keys.

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
- `x` as the peer-bound session-key encrypted frame prefix
- `h` as the advertising-peer recipient marker
- `c` as the joining-peer recipient marker

In version 1, the character `h` is reused in two different positions: once as a frame prefix and once as a recipient marker.
These meanings are distinguished by position within the frame.

Receivers MUST ignore frames where `recipient` does not match the local role.

### Signaling Messages

After decryption, a signaling payload MUST be valid JSON containing:

- `type`: one of `flash`, `pubkey`, `capabilities`, or `data`
- `payload`: defined below based on `type`.
- `timestamp`: time in milliseconds since Unix epoch.

The signaling message types have the following meanings:

- `flash`: sent by the joining peer to begin the handshake
- `pubkey`: carries a peer public key
- `capabilities`: acknowledges the previous handshake step, negotiates the transport, and carries optional peer metadata
- `data`: carries post-handshake signaling payloads, including transport negotiation objects

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

### Handshake Sequence

The version 1 handshake sequence is:

1. The joining peer sends `flash` with a fresh 16-byte nonce encoded as 32 lowercase hex characters under the bootstrap key.
2. The advertising peer sends `pubkey` containing its serialized X25519 public key, the client nonce and a fresh host nonce under the bootstrap key.
3. The joining peer verifies the host key against `h` and sends its own `pubkey`, with both nonces, under the bootstrap key.
4. Both peers derive directional session keys. The host sends `capabilities` under its signaling send key; the client verifies it and sends its own `capabilities` under its signaling send key.
5. A peer accepts the other only after receiving its authenticated capabilities. Subsequent signaling data uses the established session keys.

Signaling is lossy. Implementations retransmit the same handshake frame every two seconds and respond to valid duplicates with the cached response. A client whose final capabilities were lost answers a duplicate host capabilities frame with the same cached ciphertext.
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
Version 1 defines the types `request`, `ack`, `response`, `failed`, and `close`.

A receiver MUST ignore a session message whose `type` it does not recognise.

The `payload` member of a session message is an opaque JSON value.
The session layer MUST NOT inspect or modify `payload`.
The application that uses the session defines what `payload` contains.
For EIP-1193 traffic, each `payload` is a JSON-RPC 2.0 request or response, carried unchanged.

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

The receiver MUST send exactly one `response` or `failed` for each `request`, with the same `messageId`:

```json
{ "type": "response", "messageId": "5b0e6f3c...", "payload": { "jsonrpc": "2.0", "id": 1, "result": ["0x1234567890abcdef1234567890abcdef12345678"] } }
```

If the receiver cannot answer, it sends `failed` instead, and the sender MUST fail the request.
A `failed` MUST NOT carry error details:

```json
{ "type": "failed", "messageId": "5b0e6f3c..." }
```

A sender MUST accept a `response` or `failed` that arrives without a prior `ack`.
A sender MUST ignore an `ack`, `response` or `failed` whose `messageId` does not match one of its open requests.
A sender SHOULD fail a request that receives no `ack` within a bounded interval.
The `ack` separates a lost message from a slow user, so a sender SHOULD NOT apply a short deadline after the `ack` arrives.

Either peer MAY end the session by sending `{ "type": "close" }` before it closes the transport.
A `close` has no `messageId` and is not acknowledged.
After a peer sends or receives `close`, it MUST NOT send further session messages and MUST fail its open requests.


### Session Resumption

Peers MAY persist the session ID, signaling parameters, local static keypair, pinned remote public key, selected transport, invitation key and separate resumption secret. These are sensitive credentials.

To resume, peers perform the same `flash`/`pubkey`/`capabilities` exchange with fresh host and client nonces, using the saved resumption secret for bootstrap and key derivation. They MUST verify the received public key against the pinned peer key. A failed resumption MUST NOT fall back to fresh pairing; a new pairing requires a new out-of-band invitation.

The resumption secret is derived from the original key agreement and invitation key, so the invitation alone cannot resume an existing pairing. The same secret is retained across successful resumes.

### Cryptography

Bootstrap messages use AES-GCM with a fresh random 12-byte IV and the hex-decoded bootstrap secret as the key: 16 bytes for initial pairing, 32 bytes for resumption. The UTF-8 signaling prefix and recipient are authenticated as associated data. Ciphertext is serialized as `base64(iv || ciphertext || tag)`.

For peer-bound keys, compute X25519 between the local static secret and pinned remote public key; reject invalid, low-order or all-zero shared secrets. Concatenate this 32-byte shared value and the hex-decoded bootstrap secret as HKDF input key material. HKDF-SHA256 uses 32 zero bytes as salt and derives 32 bytes per key. Its UTF-8 `info` is:

```text
JSON.stringify(["openlv peer keys", 1, sessionId, "host", hostPublicKey, "client", clientPublicKey, purpose, hostNonce, clientNonce])
```

Public keys are canonical Base64-encoded raw X25519 keys; nonces are lowercase hex. The four `purpose` values are `signaling:host-to-client`, `signaling:client-to-host`, `transport:host-to-client`, and `transport:client-to-host`.

The original pairing derives its 32-byte resumption secret using the same input and salt, with `purpose` set to `resumption` and both nonce fields omitted from the JSON array. On resumption the saved resumption secret is retained.

Session frames use AES-256-GCM. Each directional key has a 64-bit counter starting at zero; its 12-byte IV is four zero bytes followed by the counter in big-endian order. Signaling authenticates the UTF-8 prefix and recipient as associated data. Frames are `base64(iv || ciphertext || tag)`. A sender MUST NOT reuse a counter with a key or send after exhaustion. A receiver MUST authenticate before recording a counter and reject duplicates and frames outside a 256-message replay window.

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
    const { id } = message as { id: number | string | null };

    return { jsonrpc: "2.0", id, result: "ok" };
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

Fresh nonces and authenticated counters prevent replay across handshakes and within a session. The static X25519 key agreement does not provide forward secrecy, which is acceptable for the intended use case of wallet-dapp connectivity, given that the session is short-lived and the bootstrap secret is ephemeral.

Persisted session state is sensitive and SHOULD be stored using the strongest platform protections available.
Implementations SHOULD allow users to disconnect and delete saved session state.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
