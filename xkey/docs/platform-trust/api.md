# Platform Trust — API

> **Status: NORMATIVE** · Feature: `platform-trust` · Module: `go-xkms/xkey` · Last verified: 2026-08-19

Transport shapes:
[`../../../docs/key-management/api.md`](../../../docs/key-management/api.md).

## Mostly a client, with one endpoint it calls

The bootstrap half is a **library call**, not a wire call: `xkey trust
bootstrap` runs `go-xkms/pkg/trust/bootstrap.Fetch`, which speaks DNS, Noise or
pinned TLS to reach an anchor. The truststore half is local state.

The one endpoint involved:

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded | Auth |
|---|---|---|---|---|---|---|
| Fetch CA bundle (bootstrap route) | `GET /v1/ca/bootstrap` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | `bootstrap.Fetch(ctx, cfg)` | **public** |
| Fetch CA bundle (authenticated) | `GET /api/v1/ca/bundle` | `GetCABundle` | same as REST | `xkms.ca.bundle` | `CAService.GetCABundle` | session |

`xkey trust import-platform <host:port>` uses `GET /api/v1/ca/bundle` over
**SPKI-pinned TLS**. The wire contract with go-trusted-platform is exactly this
— a pinned fetch of a public bundle, and **no Go import in either direction**.

Why the bootstrap route has no gRPC or MCP form is covered in
[`../../../docs/trust-bootstrap/api.md`](../../../docs/trust-bootstrap/api.md):
a client with no trust and no credentials has HTTP and little else.

## Bootstrap modes

`--method dane,noise,spki,direct` maps to the dispatch library's `Mode` values,
which are deliberately identical to the CLI verb and SDK accessor names so the
three cannot drift. Semantics, anchors and the per-mode configuration are in
[`../../../docs/trust-bootstrap/api.md`](../../../docs/trust-bootstrap/api.md).

`--timeout` (default `60s`) bounds the whole operation including fallbacks;
per-method bounding is `Config.PerMethodTimeout` on the library side.

## Local state, not an API

| Thing | Where | Notes |
|---|---|---|
| Stored certificates, purposes, sources | `xkey/pkg/truststore` | keyed by fingerprint |
| NSS database integration | `xkey/pkg/nssdb` | `trust install` / `uninstall` |
| OS trust store | system-dependent | mutated by `trust install` |

There is no network API for the truststore, and there should not be: a remote
"add a trust anchor" call is a remote "trust this" call.

## Error mapping

Bootstrap returns the library's typed errors — `ErrInvalidMode`,
`ErrModeNotConfigured`, `ErrServerURLRequired`, and `*FetchError` (carrying the
attempted `Mode`, matching `ErrFetch`, unwrapping to the truststrap cause).

The `import-platform` path additionally fails on an SPKI mismatch, before
anything is stored.

| Condition | Result |
|---|---|
| SPKI pin mismatch | nothing stored; **investigate rather than retry** |
| DANE record does not validate | that method fails; others may still be tried |
| method not configured | skipped silently under multi-method dispatch |
| unknown fingerprint | local error |
| missing `--purpose` on classify | flag validation error |

## Versioning

`/v1/ca/bootstrap` sits on its own prefix, deliberately — it is the one route a
bare client hard-codes, versioned independently of the authenticated API.

The purpose vocabulary is xkey's own and is a closed set. Adding a purpose is
additive; removing or renaming one invalidates existing classifications, which
is a data migration rather than a code change.
