---
"@openlv/core": minor
---

Compute the URI `h` parameter as the first 16 hex characters of SHA-256 of the 32 raw X25519 public-key bytes, as `specs/erc-x.md` requires, instead of hashing the key's base64 text. This changes `h` for every key, so pairing with 0.2.0 peers breaks: they reject the new `h`, and this version rejects theirs.
