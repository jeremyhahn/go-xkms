# Platform Trust — API

> **Status: NORMATIVE** · Feature: `platform-trust` · Module: `go-xkms/xkey` · Last verified: 2026-09-25

Transport shapes:
[`../../../docs/key-management/api.md`](../../../docs/key-management/api.md).

## Mostly a client, with one endpoint it calls

Both halves are **library calls**, not two different protocols: `xkey trust
bootstrap` runs `go-xkms/pkg/trust/bootstrap.Fetch`, which speaks DNS, Noise or
pinned TLS to reach an anchor by trying an ordered method chain. `xkey trust
fetch`/`import-platform` run `go-xkms/pkg/trust/fetcher.Fetch`
(`xkms.TrustFetcherFetch`), a single-method HTTPS client that only ever
verifies by SPKI pin — no dispatch, no fallback. The truststore half is local
state, for both.

The one endpoint involved:

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded | Auth |
|---|---|---|---|---|---|---|
| Fetch CA bundle (bootstrap route) | `GET /v1/ca/bootstrap` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | `bootstrap.Fetch(ctx, cfg)` | **public** |
| Fetch CA bundle (authenticated) | `GET /api/v1/ca/bundle` | `GetCABundle` | same as REST | `xkms.ca.bundle` | `CAService.GetCABundle` | session |

`xkey trust fetch <url>` hits whatever URL the operator supplies.
`xkey trust import-platform <host:port>` builds and hits
`https://<host:port>/v1/ca/bootstrap` — the **public, unauthenticated**
bootstrap route, the same one `trust bootstrap`'s `direct`/`spki` modes reach,
not the session-authenticated `/api/v1/ca/bundle` row above. Both go through
`pkg/trust/fetcher.Fetch` over **SPKI-pinned TLS**, never through
`pkg/trust/bootstrap`'s dispatch chain. There is **no Go import** between
xkey and whatever go-xkms-based server it bootstraps trust from, in either
direction — the wire contract is exactly this: a pinned GET of a public
bundle.

`pkg/trust/fetcher`'s doc comment (`pkg/trust/fetcher/fetcher.go:44`) records
why the default moved off `/api/v1/ca/bundle`: that route only worked
unauthenticated while adaptive authentication served it anonymously, and the
canonical first-boot ceremony closes that window by creating the
administrator at startup. `trust fetch <url>` will still send a GET to
whatever URL you give it, including `/api/v1/ca/bundle`, but the fetcher
attaches no session credential (no `--extra-headers`-equivalent CLI flag
exists) — once first-boot has run, that route answers with an auth failure
rather than a bundle for an unauthenticated caller, which is the intended
effect of the route move, not a `trust fetch` limitation to work around.

Why the bootstrap route has no gRPC or MCP form is covered in
[`../../../docs/trust-bootstrap/api.md`](../../../docs/trust-bootstrap/api.md):
a client with no trust and no credentials has HTTP and little else. The same
reasoning applies to `pkg/trust/fetcher`: it has no gRPC, QUIC or MCP form
either, for the same reason — first contact has no credentials to authenticate
any of those transports with.

## Bootstrap modes

`--method dane,noise,spki,direct` maps to the dispatch library's `Mode` values,
which are deliberately identical to the CLI verb and SDK accessor names so the
three cannot drift. Semantics, anchors and the per-mode configuration are in
[`../../../docs/trust-bootstrap/api.md`](../../../docs/trust-bootstrap/api.md).

`--timeout` (default `60s`) bounds the whole operation including fallbacks;
per-method bounding is `Config.PerMethodTimeout` on the library side.

## SPKI-pinned fetch (`fetch`/`import-platform`)

`pkg/trust/fetcher.Options` (`xkms.TrustFetcherOptions`) maps directly onto
the shared `fetch`/`import-platform` flag set:

| `Options` field | CLI flag | Default |
|---|---|---|
| `SPKIPin` | `--spki-pin` | — (required; `ErrPinRequired`/`ErrInvalidPin` otherwise) |
| `Timeout` | `--timeout` | `trustfetcher.DefaultTimeout` = `30s` |
| `HTTPClient` | — (not exposed) | `nil` — the fetcher builds a client pinned to `SPKIPin` |
| `ExtraHeaders` | — (not exposed) | none |

`Bundle.Source` (`"platform:" + host`) is what `--source` overrides;
`Bundle.LeafSPKI` is the value echoed in `Bundle fetched from ...` output and
is always equal to the supplied pin on success.

The client requests `Accept: application/x-pem-file, application/json;q=0.5`
and accepts either: a raw PEM response, or the platform's
`{code,error,success,payload:{bundle}}` / bare `{bundle}` JSON envelope,
base64-decoded (`pkg/trust/fetcher/fetcher.go:57-81`).

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

The `fetch`/`import-platform` path fails closed the same way, through its own,
separate error set: CLI-level sentinels `ErrTrustFetchInvalidArgs`,
`ErrTrustFetchFailed`, `ErrTrustImportPlatformFailed`, `ErrTrustHostRequired`
(`xkey/cmd/xkey/cmd/trust_fetch.go:29-43`), wrapping `pkg/trust/fetcher`'s own
`ErrInvalidURL`, `ErrInvalidPin`, `ErrPinRequired`, `ErrPinMismatch`,
`ErrHTTPStatus`, `ErrEmptyBundle`, `ErrInvalidPEM`, `ErrInvalidJSON`,
`ErrNoLeafCert` (`pkg/trust/fetcher/errors.go`) — all reachable through
`errors.Is` on the CLI-level error.

| Condition | Result |
|---|---|
| SPKI pin mismatch (`trust bootstrap --method spki`) | nothing stored; **investigate rather than retry** |
| SPKI pin mismatch (`trust fetch`/`import-platform`) | `ErrPinMismatch`; nothing stored; TLS handshake itself fails, so no bytes are ever read from the server |
| DANE record does not validate | that method fails; others may still be tried |
| method not configured | skipped silently under multi-method dispatch |
| unknown fingerprint | local error |
| missing `--purpose` on classify | flag validation error |
| missing `--spki-pin` on `fetch`/`import-platform` | `ErrTrustFetchInvalidArgs`; rejected before any network call |
| empty `<host:port>` on `import-platform` | `ErrTrustHostRequired`; rejected before a URL is built |

## Versioning

`/v1/ca/bootstrap` sits on its own prefix, deliberately — it is the one route a
bare client hard-codes, versioned independently of the authenticated API.

The purpose vocabulary is xkey's own and is a closed set. Adding a purpose is
additive; removing or renaming one invalidates existing classifications, which
is a data migration rather than a code change.
