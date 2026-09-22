- **Wire and CLI backward-compatibility shims for keys, WebAuthn, the
  barrier and PKCS#11 state are gone — BREAKING.** Five independent compat
  paths, all reachable from wire input, are deleted outright rather than
  deprecated (owner rule 2026-09-22: no backward compatibility, BREAKING is
  fine).
  - `PKCS11StateCASRequest.ExpectAbsent` (proto field 6,
    `pkg/api/grpc/proto/xkmsv1/xkms.proto`) — the field that let a CAS call
    double as `PutIfAbsent` is removed; the field number is `reserved`. The
    dedicated `PKCS11StatePutIfAbsent` RPC is the only create-if-absent path.
    Every server handler, transport (`rest`/`unix`/`grpc`/`quic`), the
    `pkg/pkcs11/module` remote-state client and the cluster CAS integration
    test are updated; none of them still set the field, so this is a
    documentation-only proto/wire change with no client migration required.
  - The WebAuthn ceremony requests' dual `email`/legacy-`username` JSON keys
    (`pkg/api/transport/types.go` `BeginRegistrationRequest`,
    `BeginAuthenticationRequest`, `FinishAuthenticationRequest`) collapse to
    a single `email` tag; `loginKeyFromWire`,
    `ErrRegistrationLoginKeyConflict` and `ErrAuthenticationLoginKeyConflict`
    are deleted. `xkey auth register`/`auth login`'s `--username` deprecated
    alias for `--email` is deleted along with its cobra deprecation plumbing.
  - `pkg/api/rest/handlers_barrier_pin.go` `BarrierInitializeRequest` /
    `BarrierUnsealRequest` lose the plaintext `secret` JSON field and its
    fallback in `barrierCredentialsFromRequest`; only the enclaved
    `password_b64` field carries the passphrase now.
  - `KeyType` is no longer read as an algorithm name when `Algorithm` is
    empty: `Algorithm` is now a required field on every `GenerateKeyRequest`
    path (`pkg/api/rest/handlers.go`, `pkg/api/grpc/service.go`, and
    `pkg/xkms/servicer_key.go`'s `buildKeyAttributes`, which backs the MCP
    and embedded transports). `KeyType` is purely a purpose
    (signing/encryption/tls/...) again. Every in-tree caller that previously
    sent only `KeyType` — `cmd/xkmsctl/key.go`'s symmetric-key path,
    `xkey/pkg/gui/services/key_service.go`, `pkg/pkcs11/module/crypto.go`'s
    two mechanism-translated generate calls, `pkg/api/mcp` handlers and its
    ~80 table-driven test literals, the `sdk/go` doc/example snippets, and
    the gRPC/REST/xkms test suites across `pkg/api/grpc`, `pkg/api/rest`,
    `pkg/xkms`, `pkg/api/transport/*` and `test/integration/*` — now sends
    `Algorithm` explicitly.
  - The FIDO2 `hmac-secret` legacy insecure derivation is gone:
    `pkg/fido2/types.go` `DerivationModeLegacyInsecure`, the
    `deriveSecretLegacy`/`legacyHMACSecret` implementation in
    `pkg/fido2/hmac_secret.go`, the `sdk/go/fido2` re-export, and
    `xkmsctl fido2 authenticate --legacy-hmac-derivation` are deleted.
    `DerivationModeCTAP2` (CTAP 2.1 §12.5) is the only derivation; a volume
    still keyed with the removed derivation must be re-enrolled.

  The xkey GUI's `GenerateKeyParams.KeyType` field and its purpose/algorithm
  fallbacks are deleted as well: `GenerateKeyDialog.svelte` now sends the
  selected algorithm as `algorithm` and leaves `purpose` unset, so the server
  applies its SIGNING default exactly as before.

  Docs: `docs/webauthn/{api,engineering}.md`, `docs/fido2/README.md`,
  `docs/fido2-ctap2/{user,cli,api,engineering}.md`,
  `xkey/docs/headless-webauthn/{cli,engineering,user}.md`.
