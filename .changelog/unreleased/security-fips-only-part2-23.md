- **A second pass closed the remaining test-suite gaps** across
  `pkg/encoding/jwe`, `pkg/keyprovider/symmetric`, `pkg/ssh/console`,
  `pkg/ssh/session`, `pkg/api/transport/usb`, `pkg/backend/software`,
  `pkg/api/mcp`, `pkg/xkms` (2,643 tests) and `pkg/tpm2/store`: every test
  that previously errored or hung behind a FIPS-only refusal it did not
  expect now either passes or asserts the expected refusal against the
  deliberately non-approved construction it exercises (RSA-OAEP-SHA1, RSA
  PKCS#1 v1.5 encryption, ANSI X9.63/SHA-1 key derivation,
  `crypto.allow_weak_hashes` / `crypto.allow_legacy_key_wrap` staying inert
  once the Go Cryptographic Module's own boundary is the ceiling,
  Ed25519ctx/ph, and the SSH/WebSocket handshake surfaces already covered by
  the first pass's `requireX` pattern). Along the way this surfaced and
  fixed a genuine, previously-undiscovered production bug, not a test
  artifact: **`GCMNonceMode` — the field recording which AEAD construction
  (arbitrary-IV or `NewGCMWithRandomNonce`) produced a symmetric ciphertext,
  needed by `Decrypt` to reconstruct the matching construction — was dropped
  by the gRPC, REST and MCP wire transports.** A default (no-explicit-nonce)
  symmetric `Encrypt` under `fips140=only` therefore produced a ciphertext
  its own matching `Decrypt` call could not open over any of those three
  transports, even though both endpoints individually behaved correctly;
  the embedded and in-process MCP transports were unaffected, since they
  forward the same `transport.EncryptResponse`/`DecryptRequest` values
  directly. Fixed by threading the field through `xkms.proto` (regenerated),
  REST and MCP JSON types, and all four SDK transport client implementations
  (`pkg/api/transport/{grpc,rest,unix,quic}`). `pkg/xkms`'s own AES-GCM
  key-wrap blob format (`wrapAESGCM`/`unwrapAESGCM`) carried the identical
  gap internally; fixed with a breaking one-byte mode-marker prefix on the
  wrapped blob (`aesGCMWrapModeExplicit`/`aesGCMWrapModeRandom`), consistent
  with this repository's pre-release, no-backward-compatibility posture. See
  `docs/fips/README.md` ("Random-nonce GCM for the default Encrypt path")
  for the full wire-format description.

  The `fips` CI job stays withheld (go-xkms#23 remains open). Two kinds of
  failure remain, both out of this repository's reach to fix directly:
  `pkg/pkcs11/module`'s `CKM_AES_GCM` mechanism surface is broader than the
  authenticated-wrap verbs alone — PKCS#11 v3.0 takes the GCM IV from the
  caller via `CK_GCM_PARAMS` with no random-nonce mode to opt into, so
  nearly the whole mechanism is arbitrary-IV GCM (295 failures at last
  measurement) — and `github.com/google/go-tpm` v0.9.8 still panics inside
  its own TPM2 session machinery on ordinary, spec-compliant use
  (`crypto/hmac` short/empty session auth, `crypto/cipher` CFB parameter
  encryption); this pass found that one such panic aborts the whole test
  *binary*, silently preventing the majority of `pkg/xkms`'s 2,643 tests
  from ever running under `fips140=only` unless the triggering test is
  skipped first. A related but non-fatal finding: `gorilla/websocket`'s
  SHA-1 `computeAcceptKey` also panics under `fips140=only`, recovered by
  `net/http` per-connection rather than crashing the process, but failing
  every WebSocket upgrade through `pkg/ssh/console` in that mode. Two open
  architecture questions surfaced for the owner rather than resolved
  unilaterally: `pkg/ssh/session`'s intentionally un-pinned
  `curve25519-sha256` KEX offer, and `pkg/api/transport/usb`'s Noise
  handshake being hard-wired to Curve25519 with no FIPS-approved substitute
  DH function in the pattern. See `docs/fips/README.md` ("Known blockers
  outside this repository's control") for the full detail.
