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
- Signaling ignores bootstrap messages once a peer key is pinned; old pairing URIs and recorded capabilities cannot bypass authenticated resumption, while unpinned hosts still accept interrupted-scan retries
- Session: saved sessions include the negotiated transport so resumed peers select the same transport without re-exchanging capabilities; an inbound `close` tears down the whole session
- Provider: settings use `storage`, while saved sessions use the optional `sessionStorage` adapter (falling back to `storage`); browsers default to localStorage, and the docs isolate dApp and wallet state per tab
- Core: persisted session parameters validate the replay counters and selected transport; malformed or incomplete saved state is rejected before signaling instead of starting a fresh handshake with restored keys
- Authentication failures and 45-second resume deadline expiry invalidate saved pairings; transient network failures retain replay counters for a later restore. Counter updates persist before publication, and write failures abort sending.
- Transport construction and session lifecycle stay inside `createSession`, without a hook wrapper or circular transport getter; the request/reply sequence lives in the existing messages module
- Saved pairing/transport identifiers reject empty and oversized values; confirmation proofs require 64 lowercase hex characters
- Core exports shared object and replay-counter type guards used by saved-state validation, signaling payload parsing, and the resume controller
- Signaling uses the existing Noble hex encoder for transcript proofs; resume tests share role-aware peer and attacker fixtures instead of duplicating setup
- Session API types and status definitions are colocated with `createSession`
- Concurrent provider restores share completion through account and chain readiness, including synchronous status-subscriber reentry and account requests during automatic restoration
- Counters for existing saved pairings persist before frame publication even when automatic reconnection is disabled; new unsaved pairings remain unsaved
- Wallet refresh waits for injected-provider discovery and authorization, then resumes with bounded retries using the newest persisted counters; lifecycle logic lives in `WalletSession.ts` independently of the connected UI
- Wallet resume registers cancellation before the first await, preventing React effect replay from creating concurrent attempts with duplicate replay counters or mismatched challenges
- `session.close({ notifyPeer: false })` supports local cleanup before retry without ending the peer's pairing; explicit End/Disconnect and clean peer close still unpair, and clean peer close resets the client's session panel just like End
- Automatic provider restoration remains enabled by default; applications can opt out through storage settings
