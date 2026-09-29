# Platform Trust — Architecture

> **Status: NORMATIVE** · Feature: `platform-trust` · Module: `go-xkms/xkey` · Last verified: 2026-09-29

## The problem

A desktop that has never spoken to the platform needs its CA bundle before it
can verify anything — and it needs to know *which* certificates it is trusting
and *for what*. A flat "trusted roots" pile answers the first question and not
the second: a TPM manufacturer root and a user CA are both "trusted", and
treating them interchangeably is how a device attestation gets accepted from
something that only proves it is a person.

## Shape chosen: bootstrap dispatch, then a classified local truststore

Two halves.

**Bootstrap** — `xkey trust bootstrap` runs the same dispatch library the rest
of the stack uses, `go-xkms/pkg/trust/bootstrap`
([`../../../docs/trust-bootstrap/architecture.md`](../../../docs/trust-bootstrap/architecture.md)),
with `--method dane,noise,spki,direct`. Nothing is reimplemented here; xkey is a
client of that library, which is the architecture rule between the modules.

**A classified truststore** — every certificate xkey holds carries a **purpose**:

| Purpose | What it is trusted for |
|---|---|
| `general` | ordinary TLS |
| `tpm-manufacturer` | anchoring TPM endorsement keys |
| `android-hardware` | anchoring Android hardware attestation |
| `user-ca` | user and client certificates |
| `bootstrap-ca` | the trust-bootstrap path |
| `idevid-issuer` | IDevID issuance |
| `synced` | nothing — received from a paired device by sync, quarantined until reclassified |

`xkey trust classify <fingerprint> --purpose <purpose>` sets it, and
`--purpose` is a **required** flag on that verb. A certificate without a purpose
is not a universal trust anchor; it is an unclassified one.

**Sync never chooses a purpose.** Certificates a paired device sends through
`remote.syncTrustStore`, `xkey device sync`, or CA sync are stored as `synced`
(`xkey/pkg/sync/service.go`, `syncedImportOptions`), never auto-classified: a
phone is a peer, not an authority over this host's roots. `synced` is absent
from the TLS anchor set (`tlsAnchorPurposes`, `xkey/pkg/truststore/import.go`)
and refused by the attestation verifier's pool builder
(`truststore.IsAnchorPurpose`), so it anchors nothing until the operator
reclassifies it.

**Auto-classification never trusts a name.** A certificate added without
`--purpose` is classified by `truststore.ClassifyCertificate`. It files a
certificate as `android-hardware` only when it carries the Android key
attestation extension or is byte-identical to an embedded Google Hardware
Attestation Root — never because its issuer DN says "Google" and
"Attestation", which anyone can write into a self-signed certificate.

`xkey trust import-platform <host:port>` and `xkey trust fetch <url>` are the
shorthand for the whole flow against a platform instance: fetch the bundle
over SPKI-pinned TLS and (optionally) install it, with **no TOFU**. They do
**not** go through the bootstrap dispatch library above — they call a
separate, lower-level go-xkms package, `pkg/trust/fetcher`
(re-exported as `xkms.TrustFetcher*`), a single-method HTTPS client that only
ever verifies by SPKI pin. `pkg/trust/bootstrap` and `pkg/trust/fetcher` are
two independent packages: the former dispatches across DANE/Noise/SPKI/Direct
looking for the first method that verifies; the latter has exactly one
verification method and no fallback.

Rejected alternatives:

- **A flat trust store.** Rejected — see the problem statement. Purpose is what
  keeps an attestation anchor from being a login anchor.
- **Reimplementing bootstrap in xkey.** Rejected by the module rule: reusable
  logic lives in `go-xkms/pkg/*` and xkey consumes it through
  `go-xkms/sdk/go`.
- **Trust on first use.** Rejected for the platform import path specifically;
  the whole point of the pinned fetch is that nothing is trusted because it
  answered first.

## Component boundaries

| Piece | Where |
|---|---|
| Bootstrap dispatch | `go-xkms/pkg/trust/bootstrap` |
| SPKI-pinned direct fetch | `go-xkms/pkg/trust/fetcher` |
| Local truststore | `xkey/pkg/truststore` |
| OS/NSS trust integration | `xkey/pkg/nssdb` |
| CLI | `xkey/cmd/xkey/cmd/trust.go`, `xkey/cmd/xkey/cmd/trust_fetch.go` |
| Platform CA import | `xkey trust fetch`/`import-platform`, over SPKI-pinned TLS |
| Attestation anchors | `go-xkms/pkg/attestation/truststore` |

Capability row: **"Trust bootstrap + platform CA import (SPKI-pinned, no TOFU)"**
— `xkey trust bootstrap|fetch|import-platform`.

The platform relationship is **wire-only**: `xkey trust fetch`/
`import-platform` fetch `GET /v1/ca/bootstrap` (the fetcher's
`DefaultBundlePath` — go-xkms's own *unauthenticated* first-contact route,
served by whichever go-xkms-based server the operator points at, not
specifically go-trusted-platform) over SPKI-pinned TLS. There is no Go import
between xkey and any server it bootstraps trust from, in either direction.

## Data flow

```
xkey trust bootstrap --method dane,noise,spki --timeout 60s
   → go-xkms/pkg/trust/bootstrap.Fetch  (first configured method that verifies)
   ← CA bundle
   → xkey/pkg/truststore: stored, fingerprinted

xkey trust classify <fingerprint> --purpose tpm-manufacturer
   → the certificate becomes an anchor for that purpose only

xkey trust install <fingerprint>
   → xkey/pkg/nssdb + OS trust store: the system and browsers now trust it

xkey trust fetch https://kms.example.com:8443/v1/ca/bootstrap --spki-pin <hex>
xkey trust import-platform kms.example.com:8443 --spki-pin <hex>
   → go-xkms/pkg/trust/fetcher.Fetch (SPKI pin only, no dispatch, no fallback)
   → SPKI-pinned TLS → GET /v1/ca/bootstrap → store (+ optional OS install with --install-system)
```

`import-platform` builds the URL from `<host:port>`; `fetch` takes any URL, so
it also reaches a non-canonical bundle endpoint an operator has configured.

## Trust boundaries

- **The anchor is out of band.** DANE needs a validating resolver; `spki` and
  `noise` need a value handed to you through a channel you already trust;
  `direct` trusts the public web PKI and nothing more.
- **Purpose is enforcement, not a label.** A `general` certificate is not an
  attestation anchor. Classifying broadly to make something work is how
  attestation stops meaning anything.
- **`trust install` reaches outside xkey.** It writes into the OS and NSS trust
  stores, so it affects every application on the machine, not just xkey.
  `uninstall` is the reverse.
- **`import-platform` does not TOFU.** It verifies by pin before storing.
- **Fingerprints are the identity.** `remove`, `show`, `classify`, `install` and
  `uninstall` all take a fingerprint, not a name — names are attacker-chosen.

## What this feature deliberately does not do

- **It does not implement DANE, Noise or SPKI pinning** — go-truststrap does,
  through go-xkms's dispatch library.
- **It does not trust on first use** on the platform import path.
- **It does not decide purposes for you.** `classify --purpose` is required
  precisely so the choice is made.
- **It does not manage the platform's CA** — it consumes the bundle.
