---
"@openlv/core": minor
"@openlv/signaling": minor
"@openlv/session": patch
"@openlv/provider": patch
---

Add durable session connection state validation.

Reject saved sessions with low-order X25519 peer public keys before restoration. Validate key agreement as well as local keypair consistency and the protocol hash.

Keep malformed bootstrap URLs out of error causes so logging or inspecting a parsing error cannot expose the handshake key.

Consolidate peer metadata, capabilities, and wire-limit validation in `@openlv/core`. Signaling and session consumers now use that shared implementation. Imports of `PeerInfo`, `PeerCapabilities`, and `validatePeerInfo` from `@openlv/signaling` must move to `@openlv/core`; replace signaling's `parseCapabilities` and `MAX_ICON_LENGTH` with core's `parsePeerCapabilities` and `MAX_PEER_ICON_LENGTH`. The session package continues to expose `PeerInfo` as part of its session interface.
