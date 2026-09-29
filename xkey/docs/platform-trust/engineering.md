# Platform Trust — Engineering Contract

> **Status: NORMATIVE** · Feature: `platform-trust` · Module: `go-xkms/xkey` · Last verified: 2026-09-29

## Exported surface

| Piece | Package |
|---|---|
| Local truststore | `xkey/pkg/truststore` |
| OS / NSS integration | `xkey/pkg/nssdb` |
| Bootstrap dispatch (consumed) | `go-xkms/pkg/trust/bootstrap`, re-exported as `xkms.TrustBootstrap*` in `sdk/go/trust.go` |
| SPKI-pinned CA-bundle fetcher (consumed) | `go-xkms/pkg/trust/fetcher`, re-exported as `xkms.TrustFetcher*` in `sdk/go/trust.go` |
| Attestation anchors (consumed) | `go-xkms/pkg/attestation/truststore` |
| CLI | `xkey/cmd/xkey/cmd/trust.go` (`list`/`add`/`remove`/`show`/`bootstrap`/`classify`/`install`/`uninstall`), `xkey/cmd/xkey/cmd/trust_fetch.go` (`fetch`/`import-platform`) |

`pkg/trust/bootstrap` and `pkg/trust/fetcher` are two separate go-xkms
packages, not one library used two ways: `trust bootstrap` runs the
DANE/Noise/SPKI/Direct dispatch chain; `trust fetch`/`trust import-platform`
call the fetcher directly and only ever verify by SPKI pin — there is no
dispatch, no DANE, no Noise on that path.

## Certificate purposes

The closed set, from `trustAddCmd`'s `--purpose` help
(`xkey/cmd/xkey/cmd/trust.go:323`):

```
general | tpm-manufacturer | android-hardware | user-ca | bootstrap-ca | idevid-issuer | synced
```

`synced` is the quarantine every certificate arriving through sync is stored
under (`xkey/pkg/sync/service.go`, `syncedImportOptions`, through
`TrustStoreAccessor.ImportPEM`). `truststore.IsAnchorPurpose` is false for it,
and the attestation verifier's pool builder refuses it with
`ErrUnsupportedPurpose`; it is absent from `tlsAnchorPurposes`.

`--purpose` is **required** on `trust classify`
(`MarkFlagRequired("purpose")`), and optional on `trust add`.

## CLI contract

| Verb | Flags |
|---|---|
| `trust list` | — |
| `trust add <pem-file>` | `--purpose`, `--source` (e.g. `manual`, `url:…`, `file:…`) |
| `trust remove <fingerprint>` | — |
| `trust show <fingerprint>` | — |
| `trust bootstrap` | `--method` (string slice: `dane`, `noise`, `spki`, `direct`), `--timeout` (default `60s`) |
| `trust classify <fingerprint> --purpose <purpose>` | `--purpose` **required** |
| `trust install <fingerprint>` | — |
| `trust uninstall <fingerprint>` | — |
| `trust fetch <url>` | `--spki-pin` **required**, `--purpose` (default `bootstrap-ca`), `--source` (default `platform:<host>`), `--install-system`, `--timeout` (default `30s`) |
| `trust import-platform <host:port>` | same flag set as `trust fetch` — `--spki-pin` **required** |

There is no `trust test` verb. `trustCmd.AddCommand` registers exactly the ten
verbs above (`xkey/cmd/xkey/cmd/trust.go:324`,
`xkey/cmd/xkey/cmd/trust_fetch.go:109`); `trustTestCmd` in
`tpm_signer_trust_test.go` is an unrelated Go-test helper function name, not a
CLI command.

`fetch`/`import-platform` register their flags through the single
`registerTrustFetchFlags` function (`xkey/cmd/xkey/cmd/trust_fetch.go:115`),
so the two verbs can never drift on flag names or defaults.

`--method` takes the same mode names as the dispatch library, which is the point:
`Mode` values there are pinned to the CLI verb and SDK accessor names so the
three cannot drift
([`../../../docs/trust-bootstrap/engineering.md`](../../../docs/trust-bootstrap/engineering.md)).

## Invariants

- **Bootstrap is delegated, never reimplemented.** `trust bootstrap` calls
  `go-xkms/pkg/trust/bootstrap`. A second protocol implementation in xkey is a
  boundary violation.
- **Purpose gates use.** A certificate classified `general` must not be accepted
  as a `tpm-manufacturer` anchor. Widening a purpose to make something work
  removes the guarantee the purpose existed for.
- **A paired device never picks an anchor.** Sync writes only through
  `TrustStoreAccessor.ImportPEM` with `PurposeSynced`; the accessor does not
  expose the auto-classifying `AddPEM` at all
  (`TestSyncTrustStore_ForgedGoogleRootAnchorsNothing`,
  `xkey/cmd/xkey/cmd/sync_trust_quarantine_test.go`).
- **`android-hardware` is never inferred from names.** `ClassifyCertificate`
  grants it for the Android key attestation extension OID or an exact match
  against the embedded Google roots only
  (`TestClassifyCertificate_ForgedGoogleAttestationRootIsNotAndroidHardware`,
  `TestClassifyCertificate_EmbeddedGoogleRootsAreAndroidHardware`).
- **`import-platform` verifies by SPKI pin before storing. No TOFU.**
- **`fetch`/`import-platform` never accept an unpinned connection.**
  `--spki-pin` is validated before the HTTP client is even built
  (`executeTrustFetch`, `xkey/cmd/xkey/cmd/trust_fetch.go:165`); there is no
  `--insecure-first-touch` flag, and a fresh command build never has one
  (`TestTrustFetchCmd_NoTOFUFlag`, `TestRegisterTrustFetchFlags`,
  `xkey/cmd/xkey/cmd/trust_fetch_test.go:144,322`).
- **Session resumption is disabled on the pinned fetch path**, deliberately.
  `pkg/trust/fetcher.BuildTLSConfig` sets `SessionTicketsDisabled: true`
  because a resumed TLS session skips `VerifyPeerCertificate`, which would
  silently bypass the pin (`pkg/trust/fetcher/spki.go:92`).
- **Fingerprints identify certificates**, everywhere in this surface. Never key
  on subject or a friendly name.
- **`trust install` mutates system state** — the OS trust store and the NSS
  database — and affects every application on the machine. It must be
  reversible: `uninstall` is not optional.
- **`--timeout` bounds the whole bootstrap**, across method fallbacks, not each
  attempt.
- **`trust add` reports added and skipped separately.** `addPEMWithOptions`
  returns both counts, and a certificate already in the store is a skip, not a
  silent nothing. A bare `added: 0` cannot distinguish "already present" from a
  parse failure, an empty file, or a permissions problem, so a file that yields
  no certificate at all is `ErrTrustNoCertificates` rather than a zero count.
- **The trust store is the CA source `xkey auth` uses for TLS.** A certificate
  added here is trusted by `auth register` and `auth login`; see
  [`../headless-webauthn/engineering.md`](../headless-webauthn/engineering.md).
  The store is read, not merely written — that was the defect in #250.
- **Concurrency.** Truststore operations serialise; `install`/`uninstall` touch
  shared system state and must not run concurrently with each other.

## Error semantics

Bootstrap failures come back from the dispatch library as `*FetchError`
carrying the attempted `Mode` and the truststrap cause — `errors.Is(err,
ErrFetch)` for any fetch failure. Local failures are `xkey/pkg/truststore`'s.

`trust add` fails with `ErrTrustPEMReadFailed` (unreadable file),
`ErrTrustAddFailed` wrapping `ErrTrustNoCertificates` (the file held no
certificate), or `ErrTrustAddFailed` wrapping the store's own error.

The distinction that matters under `--method a,b,c`: a mode that was **not
configured** is skipped silently, while a mode that was tried and **failed** is
reported. Those have completely different remediations, and `FetchError.Mode` is
what tells them apart.

**Fail closed:** an SPKI mismatch, a DANE record that does not validate, a Noise
key mismatch, or an unverifiable bundle all refuse to store anything.

`fetch`/`import-platform` errors are all typed sentinels declared in
`xkey/cmd/xkey/cmd/trust_fetch.go:29-43`:

| Sentinel | When |
|---|---|
| `ErrTrustFetchInvalidArgs` | missing/blank `--spki-pin`, or an unparseable `--purpose` |
| `ErrTrustFetchFailed` | the HTTP/TLS fetch failed, or a fetched certificate could not be added to the store |
| `ErrTrustImportPlatformFailed` | wraps a failure from the underlying `fetch` call, or a malformed built URL |
| `ErrTrustHostRequired` | `import-platform`'s `<host:port>` argument was empty or all whitespace |

Below that, `pkg/trust/fetcher` (a separate go-xkms package, not xkey's) has
its own sentinels surfaced through the wrapped error chain:
`ErrInvalidURL`, `ErrInvalidPin`, `ErrPinRequired`, `ErrPinMismatch`,
`ErrHTTPStatus`, `ErrEmptyBundle`, `ErrInvalidPEM`, `ErrInvalidJSON`,
`ErrNoLeafCert` (`pkg/trust/fetcher/errors.go`). All are reachable via
`errors.Is` through `ErrTrustFetchFailed`'s `Unwrap`.

An HTTP 5xx or connection failure reads as `trust: platform CA bundle fetch
failed: trust/fetcher: unexpected HTTP status: 500 ...`; an already-present
certificate is not an error at all — it increments the `skipped` count in the
success output instead
(`errors.Is(err, truststore.ErrCertificateExists)`,
`xkey/cmd/xkey/cmd/trust_fetch.go:219`).

## Configuration

`--method` selects and orders the bootstrap modes; `--timeout` (default `60s`)
bounds the whole operation. `--source` on `trust add` records provenance —
`manual`, `url:…`, `file:…` — which is the only record of where an anchor came
from once it is in the store.

`fetch`/`import-platform` have their own, independent `--timeout` (default
`30s`, `xkms.TrustFetcherDefaultTimeout`) — it bounds a single HTTP
transaction, not a multi-method fallback, so the default is shorter than
bootstrap's.

## Persistence

`xkey/pkg/truststore` holds certificates with their fingerprint, purpose and
source. `xkey/pkg/nssdb` handles installation into the NSS database; OS trust
store integration sits alongside it.

Installation is **outside** xkey's data: uninstalling xkey does not by itself
remove what `trust install` put into the system store.

`fetch`/`import-platform` persist through the same `xkey/pkg/truststore`
`FileStore` every other `trust` verb uses (`openTrustStore`,
`xkey/cmd/xkey/cmd/trust.go:368`) — there is no separate store for
platform-fetched certificates.

## Test strategy

- **Unit** — `xkey/pkg/truststore` and `xkey/pkg/nssdb` suites.
- **Bootstrap** — covered upstream in `go-xkms/pkg/trust/bootstrap/*_test.go`
  and `go-xkms/test/integration/bootstrap`; xkey's tests cover dispatch and
  storage, not the protocols.
- **`fetch`/`import-platform`** — `pkg/trust/fetcher/fetcher_test.go` and
  `fetcher_gaps_test.go` cover the HTTP/TLS/pin layer directly (bad pin, PEM
  vs. JSON decoding, HTTP status handling, no-leaf-cert). The CLI layer is
  `xkey/cmd/xkey/cmd/trust_fetch_test.go`: a happy path against a real
  `httptest.NewTLSServer` bound to the fetcher's own
  `xkms.TrustFetcherDefaultBundlePath` constant (a regression guard — the
  fixture and the client drifted apart once already, when the fetcher moved
  off the session-authenticated `/api/v1/ca/bundle` route), pin
  validation, purpose validation, `import-platform`'s scheme-stripping and
  empty-argument handling, and an explicit regression test that
  `--insecure-first-touch` is never reintroduced
  (`TestTrustFetchCmd_NoTOFUFlag`).

## Observability

`trust list` and `trust show` are the audit surface: fingerprint, purpose and
source per anchor. The `--source` field is the provenance record — an anchor
with `manual` and no context is one nobody will be able to justify later.

`trust install` should be logged wherever the machine's configuration is
tracked, because it changes trust for every application on the host, not just
this one.
