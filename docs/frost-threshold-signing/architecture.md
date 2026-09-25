# FROST Threshold Signing — Architecture

> **Status: NORMATIVE** · Feature: `frost-threshold-signing` · Repo: `go-xkms` · Last verified: 2026-09-24

## The problem

Shamir-style share custody (`docs/share-custody/`) reconstructs the private
key at signing time, even if only in an enclave: every signature has one
moment where the whole key exists. FROST (RFC 9591, "Flexible Round-Optimized
Schnorr Threshold Signatures") removes that moment. M-of-N participants each
hold a scalar share and run a two-round protocol that produces a valid
Schnorr signature the group public key verifies — the full private key is
never assembled anywhere, at generation or at signing time.

## Build tag: everything here requires `-tags frost`

Every source file under `pkg/keyprovider/frost`, `cmd/xkmsctl/frost.go`, and
the FROST-specific REST/gRPC/MCP handler files carries `//go:build frost`
(`pkg/keyprovider/frost/doc.go:14`, `cmd/xkmsctl/frost.go:14`). A default
build (`go build ./...` or `make build` without the tag) compiles a stub
instead:

- `cmd/xkmsctl/frost_stub.go` (`//go:build !frost`) registers an `xkmsctl
  frost` command whose `Run` prints "FROST support not compiled in" and
  exits 1.
- `pkg/api/rest/handlers_frost_stub.go`, the gRPC `service_frost_stub.go`,
  and the MCP `handlers_frost_stub.go` (all `//go:build !frost`) keep every
  route/RPC/method registered, but every handler returns a fixed "FROST
  support not compiled" error — REST answers `501 Not Implemented`.

`go build -tags frost ./...` compiles the real implementation everywhere.

## Two independent surfaces, not one

The single most important architectural fact about this feature is that the
CLI and the network API are **not the same code path**, and only one of them
is reachable in a stock deployment today.

```
xkmsctl frost <verb>                      REST /frost/*, gRPC Frost*, MCP frost.*
        |                                          |
        v                                          v
client.NewFrostBackend(...)               HandlerContext.getFrostBackend()
(sdk/go/frost.go type aliases over        (pkg/api/rest/handlers_frost.go:816)
 pkg/keyprovider/frost, embedded          walks s.keyProviders for a backend
 in the xkmsctl process)                  whose Type() == types.BackendTypeFrost
        |                                          |
        v                                          v
<key-dir>/frost/{public,secrets}          xkmsd's backend registry
(local files on the operator's                  |
 machine, per xkmsctl(1) invocation)      NOTHING REGISTERS ONE — see below
```

### The CLI path is local-only, every subcommand

`xkmsctl frost keygen|import|list|info|delete|round1|round2|aggregate|verify`
all call `createFrostBackend` (`cmd/xkmsctl/frost.go:1104`), which builds a
`frost.Config` from two directories under `--key-dir` —
`<key-dir>/frost/public` (group public key, verification shares, metadata)
and `<key-dir>/frost/secrets` (this operator's secret share, via a
`pkcs8`-backed file secret store) — and opens a fresh `frost.FrostBackend`
in the `xkmsctl` process itself. None of these subcommands call the SDK's
network transports; `--server`/`--transport` (which every other `xkmsctl`
command group honors) has no effect on `xkmsctl frost`. This matches
`test/integration/api/frost_parity_test.go`, whose "all protocols" keygen
test invariably passes `--transport embedded` — there is no other transport
to exercise for that verb.

### The network API path requires a daemon-side FROST backend that nothing wires up

REST (`/frost/keys`, `/frost/keys/import`, `/frost/keys/{id}`,
`/frost/keys/{id}/nonces`, `/frost/keys/{id}/sign`, `/frost/aggregate`,
`/frost/verify` — `pkg/api/rest/routes.go:164-172`), gRPC
(`pkg/api/grpc/service_frost.go`, nine RPCs), and MCP (`ssh`-style dotted
methods `frost.generateKey`, `frost.importKey`, `frost.listKeys`,
`frost.getKey`, `frost.deleteKey`, `frost.generateNonces`,
`frost.signRound`, `frost.aggregate`, `frost.verify` —
`pkg/api/mcp/handlers_frost.go:776-800`) are all real, fully implemented
handlers. Every one of them calls a `getFrostBackend()` helper
(`pkg/api/rest/handlers_frost.go:816`, `pkg/api/grpc/service_frost.go:600`)
that scans the daemon's registered backends for one whose `Type()` is
`types.BackendTypeFrost` and fails with "no FROST backend configured" if it
finds none.

**As shipped, nothing registers one.** `pkg/xkms/register_frost.go` (also
`//go:build frost`) registers a `newFROSTKeyProvider` factory under
`xkms.BackendFROST` for the generic `xkms.AutoInitialize`/library-embedding
path, and it accepts `threshold`/`total`/`participant_id` config keys — but
`pkg/config.BackendsConfig` (`pkg/config/config.go`) has no `Frost` field,
`configs/xkmsd.yaml` has no `backends.frost:` section, and `pkg/server` has
no `backend_frost.go` calling that factory the way `backend_pkcs11.go`,
`backend_tpm2.go`, `backend_awskms.go`, etc. call theirs. The REST/gRPC/MCP
handler unit tests that exercise a live FROST backend
(`pkg/api/rest/handlers_frost_real_test.go`) construct one by hand — a fake
`xkms.Backend` wrapping `frost.NewBackend(...)` injected directly into the
`HandlerContext`'s registry, bypassing `pkg/server` entirely — which is
exactly what an operator cannot do from `xkmsd.yaml`.

Net effect: **`xkmsctl frost` is a real, working, local threshold-signing
tool today; the REST/gRPC/MCP FROST surface is implemented but has no
supported path to make it answer anything but "no FROST backend configured"
on a stock `xkmsd`.** Wiring `backends.frost` into `pkg/config` and
`pkg/server`, or building on the SDK's `sdk/go/frost.go` type aliases (which
are compile-time re-exports of the embedded library, not a remote client —
there is no `POST /frost/...` call anywhere under `sdk/go/`), is unstarted
work, not a documented gap in an otherwise-wired feature.

## Package layout

| Package | Role |
|---|---|
| `pkg/keyprovider/frost` | The `FrostBackend` (`types.KeyProvider`), trusted-dealer key generation, the explicit round API, nonce-reuse tracking, ciphersuite math |
| `pkg/xkms/register_frost.go` | Registers `types.BackendType("frost")` with the generic backend-factory registry (`xkms.AutoInitialize`/library embedding only — not `xkmsd`) |
| `sdk/go/frost.go` | Type aliases (`FrostBackend`, `FrostConfig`, …) and constructors re-exported for `xkmsctl` and other SDK consumers — no network client |
| `cmd/xkmsctl/frost.go` | The `xkmsctl frost` command tree, entirely local |
| `pkg/api/rest/handlers_frost.go`, `pkg/api/grpc/service_frost.go`, `pkg/api/mcp/handlers_frost.go` | Network handlers over a daemon-registered `FrostBackend` — see above for why none exists by default |

## Key storage split: public vs. secret

`frost.Config` (`pkg/keyprovider/frost/config.go:24`) takes two storage
handles, matching the pattern used by `pkg/share-custody` and the sealing
strategies:

- `PublicStorage storage.Backend` — group public key, verification shares,
  per-key metadata. Not sensitive; any `storage.Backend` will do.
- `SecretBackend types.KeyProvider` — this participant's secret share.
  Production deployments should back this with a hardware `types.KeyProvider`
  (TPM 2.0, PKCS#11, cloud KMS); `xkmsctl` and the daemon factory both
  default to a software `pkcs8` backend.

## Key generation: trusted dealer only

`Config.DKG KeyGenerator` (`config.go:35`) is an extension point for a real
distributed-key-generation protocol where no single party ever sees the
whole key; if left nil, `Config.GetKeyGenerator()` falls back to
`NewTrustedDealer()` (`config.go:151-156`). **Only the trusted-dealer
generator ships today.** A custom `KeyGenerator` is something an embedder
must write and wire in themselves — see
[`dkg-integration.md`](../frost/dkg-integration.md) in the legacy folder for
worked notes on the `KeyGenerator` interface (not re-verified for this
folder; treat it as design notes, not a shipped API).

## Two signing modes

1. **Orchestrated** (`FrostBackend.Signer`) — returns a `crypto.Signer`.
   Works out of the box only for `Threshold == 1`; anything higher returns
   `frost.ErrThresholdSigningNotSupported`
   (`pkg/keyprovider/frost/errors.go`), because a synchronous `Sign` call
   cannot coordinate a multi-party protocol.
2. **Explicit round API** — `GenerateNonces` → (exchange commitments
   out-of-band) → `SignRound` → (collect ≥ threshold shares) → `Aggregate` →
   `Verify`. This is what both `xkmsctl frost round1/round2/aggregate/verify`
   and the REST/gRPC/MCP handlers drive.

## Nonce-reuse prevention

FROST nonce reuse recovers the private key outright. `Config.NonceStorage`
(falls back to `PublicStorage`) and `EnableNonceTracking` (default `true`,
`config.go:165`) make every commitment hash-checked before it is accepted a
second time; a repeat returns `ErrNonceAlreadyUsed`
(`pkg/keyprovider/frost/errors.go`). Disabling nonce tracking is documented
in the package as strongly discouraged (`pkg/keyprovider/frost/doc.go:80-83`)
and is not something either the CLI or the network handlers expose a flag
for — it is only reachable by constructing `frost.Config` directly.

## Sessions

An explicit-round signing session is created by `SignRound`'s first call for
a given `(keyID, message)` pair and expires after
`DefaultSessionTimeout = 5 * time.Minute` (`pkg/keyprovider/frost/rounds.go:44`).
An expired session surfaces as `ErrSessionExpired`; an unknown one as
`ErrSessionNotFound`.

## Rejected alternative: reusing the Shamir share-custody plane

`docs/share-custody/` already has an M-of-N custodian/share model. FROST does
not build on it, because the two protocols solve different problems: Shamir
custody protects a key that is periodically *reconstructed*; FROST exists
specifically so the key is *never* reconstructed. Sharing the storage layer
would have coupled a "the key is whole, briefly" data model to a "the key is
never whole" one for no code reuse that mattered — `frost.Config` deliberately
takes its own `PublicStorage`/`SecretBackend` pair instead of a
`custodian.Group`.
