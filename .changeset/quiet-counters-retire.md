---
"@openlv/core": minor
"@openlv/signaling": minor
"@openlv/session": minor
"@openlv/provider": minor
"@openlv/connector": minor
"@openlv/transport": minor
---

Restore durable replay counters for authenticated session resumption.

- Signaling: `resume` and `resume-ack` carry a monotonic counter; persisted high-water marks survive restart and bind the authenticated proof
- Session: saved sessions include the negotiated transport so resumed peers select the same transport without re-exchanging capabilities; an inbound `close` tears down the whole session
- Provider: saved session keys and counters use the existing `storage` adapter alongside settings, defaulting to localStorage in browsers; no separate session-storage adapter is required
- Core: persisted session parameters validate the replay counters and selected transport
- Resumption failures and 45-second deadlines terminate the pairing, surface a re-pairing error, and invalidate provider-saved state; counter persistence failures abort sending
- Transport construction and session lifecycle stay inside `createSession`, without a hook wrapper or circular transport getter; the request/reply sequence lives in the existing messages module
- Saved pairing/transport identifiers reject empty and oversized values; confirmation proofs require 64 lowercase hex characters
- Core exports shared object and replay-counter type guards used by saved-state validation, signaling payload parsing, and the resume controller
- Signaling uses the existing Noble hex encoder for transcript proofs; resume tests share role-aware peer and attacker fixtures instead of duplicating setup
- Session API types and status definitions are colocated with `createSession`; the separate types module is removed
