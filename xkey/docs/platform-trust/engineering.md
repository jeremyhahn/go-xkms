# Platform Trust — Engineering Contract

> **Status: NORMATIVE** · Feature: `platform-trust` · Module: `go-xkms/xkey` · Last verified: 2026-09-03

## Exported surface

| Piece | Package |
|---|---|
| Local truststore | `xkey/pkg/truststore` |
| OS / NSS integration | `xkey/pkg/nssdb` |
| Bootstrap dispatch (consumed) | `go-xkms/pkg/trust/bootstrap` |
| Attestation anchors (consumed) | `go-xkms/pkg/attestation/truststore` |
| CLI | `xkey/cmd/xkey/cmd/trust.go` |

## Certificate purposes

The closed set, from `trustAddCmd`'s `--purpose` help
(`xkey/cmd/xkey/cmd/trust.go:323`):

```
general | tpm-manufacturer | android-hardware | user-ca | bootstrap-ca | idevid-issuer
```

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
| `trust fetch <url>` | — |
| `trust import-platform <host:port>` | — |
| `trust test` | — |

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
- **`import-platform` verifies by SPKI pin before storing. No TOFU.**
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

## Configuration

`--method` selects and orders the bootstrap modes; `--timeout` (default `60s`)
bounds the whole operation. `--source` on `trust add` records provenance —
`manual`, `url:…`, `file:…` — which is the only record of where an anchor came
from once it is in the store.

## Persistence

`xkey/pkg/truststore` holds certificates with their fingerprint, purpose and
source. `xkey/pkg/nssdb` handles installation into the NSS database; OS trust
store integration sits alongside it.

Installation is **outside** xkey's data: uninstalling xkey does not by itself
remove what `trust install` put into the system store.

## Test strategy

- **Unit** — `xkey/pkg/truststore` and `xkey/pkg/nssdb` suites.
- **Bootstrap** — covered upstream in `go-xkms/pkg/trust/bootstrap/*_test.go`
  and `go-xkms/test/integration/bootstrap`; xkey's tests cover dispatch and
  storage, not the protocols.
- **`trust test`** — the built-in verification verb, for confirming a store
  actually validates what it should.

## Observability

`trust list` and `trust show` are the audit surface: fingerprint, purpose and
source per anchor. The `--source` field is the provenance record — an anchor
with `manual` and no context is one nobody will be able to justify later.

`trust install` should be logged wherever the machine's configuration is
tracked, because it changes trust for every application on the host, not just
this one.
