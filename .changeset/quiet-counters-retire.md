---
"@openlv/core": minor
"@openlv/signaling": minor
"@openlv/session": minor
"@openlv/provider": minor
"@openlv/connector": minor
"@openlv/transport": minor
---

Add authenticated session resumption with durable replay protection.

- Signaling: add the three-message resume exchange; ignore stale or unauthenticated frames without invalidating saved pairings, persist local counters before publishing, and persist received counters only after challenge verification.
- Session: persist the negotiated transport and require a synchronous persistence callback when resuming; a missing saved transport invalidates the pairing. Close messages are uncorrelated and unacknowledged; `close({ notifyPeer: false })` releases local resources only. Terminal closure emits a one-shot `close` event on the session emitter with the error reason and whether the pairing must be re-paired.
- Provider: persist resumable sessions using `sessionStorage` when configured, otherwise `storage`; automatic restoration is enabled by default.
- Docs: describe the resumption and storage contracts. The wallet demo subscribes to Wagmi's authorized wallet connections and restores the pairing when one appears, including after delayed wallet hydration.
