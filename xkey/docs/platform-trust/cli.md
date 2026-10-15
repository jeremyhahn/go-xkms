# Platform Trust — CLI

> **Status: NORMATIVE** · Feature: `platform-trust` · Module: `go-xkms/xkey` · Last verified: 2026-09-29

Binary: `xkey`, group `trust` (`xkey/cmd/xkey/cmd/trust.go`, plus `fetch` and
`import-platform` in `xkey/cmd/xkey/cmd/trust_fetch.go`).

## `xkey trust bootstrap`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--method` | string slice | — | methods to try: `dane`, `noise`, `spki`, `direct` |
| `--timeout` | duration | `60s` | overall timeout, across fallbacks |

```
xkey trust bootstrap --method dane,spki --timeout 60s
```

The methods are the same set as everywhere else in the stack, deliberately —
see [`../../../docs/trust-bootstrap/cli.md`](../../../docs/trust-bootstrap/cli.md)
for what each one anchors on. `direct` trusts the public web PKI and verifies
nothing else.

Every fetched certificate is filed under `bootstrap-ca` with source
`platform:<host>` (the host of `trust.bootstrap.server_url`, or the Noise
address when only Noise is configured), exactly as `trust fetch` and the GUI's
trust-strap import file it. It is never auto-classified.

## `xkey trust fetch <url>` (SPKI-pinned direct fetch)

`xkey trust fetch` and `xkey trust import-platform` (below) go through a
**different, lower-level path than `trust bootstrap`**: `pkg/trust/fetcher`
(re-exported as `xkms.TrustFetcherFetch` in `sdk/go/trust.go`), a single-method
HTTPS client that only ever verifies by SPKI pin — it does not run the
DANE/Noise/SPKI/Direct dispatch chain `trust bootstrap` does
(`xkey/cmd/xkey/cmd/trust_fetch.go:191`, `executeTrustFetch`).

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--spki-pin` | string | — | **Required.** 64-char hex SHA-256 of the server's leaf certificate SPKI. Obtain out-of-band. |
| `--purpose` | string | `bootstrap-ca` | Certificate purpose recorded for every certificate added (`truststore.PurposeBootstrapCA`, `pkg/attestation/truststore/types.go`) |
| `--source` | string | `platform:<host:port>` of the URL | Recorded provenance string, overrides the default `platform:<host>` label |
| `--install-system` | bool | `false` | After adding to the xKey trust store, install any self-signed root certificates in the bundle to the OS trust store |
| `--timeout` | duration | `30s` (`xkms.TrustFetcherDefaultTimeout`) | HTTP transaction timeout |

(`xkey/cmd/xkey/cmd/trust_fetch.go:115`, `registerTrustFetchFlags` — both `fetch`
and `import-platform` share this exact flag set.)

```
xkey trust fetch https://kms.example.com:8443/v1/ca/bootstrap \
  --spki-pin 3a7be5f1c0baf12c3d9e6a1b8f4c2d0e5a9b7c3f1e8d6a4b2c0f9e7d5c3b1a9f \
  --install-system
```

Sample output:

```
Fetching CA bundle from https://kms.example.com:8443/v1/ca/bootstrap
Bundle fetched from https://kms.example.com:8443/v1/ca/bootstrap
  certificates: 2 (added: 2, skipped: 0)
  leaf SPKI:    3a7be5f1c0baf12c3d9e6a1b8f4c2d0e5a9b7c3f1e8d6a4b2c0f9e7d5c3b1a9f
  installed to OS trust store: xkey-3a7be5f1c0baf12c (Platform Root CA)
```

`--spki-pin` is mandatory. Omitting it, or passing only whitespace, fails
before any network call:

```
$ xkey trust fetch https://kms.example.com:8443/v1/ca/bootstrap
Error: trust: invalid fetch arguments: --spki-pin is required (no trust-on-first-use path)
```

The URL's path is whatever the operator supplies — `fetch` does not assume
`/v1/ca/bootstrap`. That canonical bootstrap path is what `import-platform`
below builds for you.

## `xkey trust import-platform <host:port>`

Fetches the platform's CA bundle over **SPKI-pinned TLS** and imports it. **No
trust on first use** — if the pin does not verify, nothing is stored.

The convenience wrapper: builds `https://<host:port>/v1/ca/bootstrap` (the
fetcher's `DefaultBundlePath`) and calls the exact same logic as `fetch`
(`xkey/cmd/xkey/cmd/trust_fetch.go:145`, `runTrustImportPlatform`). Same flags
as `fetch`, above — `--spki-pin` is required here too.

```
xkey trust import-platform kms.example.com:8443 \
  --spki-pin 3a7be5f1c0baf12c3d9e6a1b8f4c2d0e5a9b7c3f1e8d6a4b2c0f9e7d5c3b1a9f \
  --install-system
```

An `https://` or `http://` prefix and a trailing `/` on the argument are
stripped, so pasting the server's own URL works too:

```
xkey trust import-platform https://kms.example.com:8443/ --spki-pin 3a7b…
```

An empty argument fails before building a URL:

```
$ xkey trust import-platform "" --spki-pin 3a7b…
Error: trust: host:port argument is required
```

A downstream failure — bad pin, unreachable host, HTTP error — is wrapped a
second time under `trust: import-platform failed:`, so the full chain reads,
for example:

```
Error: trust: import-platform failed: trust: platform CA bundle fetch failed: Get "https://kms.example.com:8443/v1/ca/bootstrap": ...
```

## `xkey trust add` / `list` / `show` / `remove`

| Verb | Flags |
|---|---|
| `trust add <pem-file>` | `--purpose`, `--source` |
| `trust list` | — |
| `trust show <fingerprint>` | — |
| `trust remove <fingerprint>` | — |

```
xkey trust add platform-ca.pem --purpose bootstrap-ca --source file:platform-ca.pem
xkey trust list -o json
xkey trust show 3fa1…  -o json
```

`add` reports both numbers -- `Certificates added: N` and, when the file held
certificates the store already had,
`Certificates skipped (already present): N`. A file holding no parseable
certificate is an error rather than a zero count, so "added: 0" always means
"already trusted" and never "nothing was read".

`--source` records where the certificate came from (`manual`, `url:…`,
`file:…`). It is the only provenance you will have later.

`trust add` reports both counts, so a zero is never ambiguous:

```
$ xkey trust add ca-chain.crt --purpose user-ca --source "file:ca-chain.crt"
Certificates added: 0
Certificates skipped (already present): 1
```

A file that yields no certificate at all — unparseable, empty, or holding only
non-certificate PEM blocks — is an error rather than a silent `added: 0`.

The store `trust add` writes is the same one `xkey auth` builds its TLS
configuration from, so adding a server's CA here is enough to let
`auth register` and `auth login` reach it. See
[`../headless-webauthn/cli.md`](../headless-webauthn/cli.md).

Everything after `add` is keyed by **fingerprint**, not by name.

## `xkey trust classify <fingerprint> --purpose <purpose>`

`--purpose` is **required**. The set:

| Purpose | Trusted for |
|---|---|
| `general` | ordinary TLS |
| `tpm-manufacturer` | anchoring TPM endorsement keys |
| `android-hardware` | anchoring Android hardware attestation |
| `user-ca` | user and client certificates |
| `bootstrap-ca` | the trust-bootstrap path |
| `idevid-issuer` | IDevID issuance |
| `synced` | nothing — received from a paired device by sync, quarantined until reclassified |

```
xkey trust classify 3fa1… --purpose tpm-manufacturer
```

`general`, `user-ca`, and `bootstrap-ca` are the purposes that anchor a TLS
server chain, so `xkey auth register` and `xkey auth login` reach a server
issued by any of them with no pin and no `--tls-ca`. The three attestation
purposes are deliberately not TLS anchors, and `synced` anchors nothing:
promote a synced certificate with `classify` only once you have checked it
yourself.

**Purpose is enforcement.** A `general` certificate will not anchor a TPM
attestation. Reclassifying something broadly to make a verification pass removes
the guarantee that verification was providing — if an attestation is failing,
the question is whether the right anchor is present, not whether this one can be
made to count.

## `xkey trust install` / `uninstall <fingerprint>`

```
xkey trust install 3fa1…
xkey trust uninstall 3fa1…
```

`install` writes into the **operating system and NSS trust stores**. Every
application on the machine — browsers included — trusts the certificate
afterwards, not just xkey. `uninstall` reverses it, and removing xkey does not.

## A first-run sequence

```
xkey trust bootstrap --method spki --timeout 60s
xkey trust list -o json
xkey trust install <fingerprint>
```

Or, given a pin obtained out-of-band instead of a truststrap configuration:

```
xkey trust import-platform kms.example.com:8443 --spki-pin <hex> --install-system
xkey trust list -o json
```

Both already file the bundle under `bootstrap-ca`; `trust classify` is only
needed to give a certificate a different purpose.

`import-platform --install-system` already installs any self-signed root in
the bundle to the OS trust store as part of the fetch, so a first run through
this path does not need a separate `trust install` step unless the bundle's
root was not self-signed in the fetched chain.

## Exit codes

`0` on success. Non-zero for an SPKI mismatch, a DANE record that does not
validate, a Noise key mismatch, an unknown fingerprint, or a missing
`--purpose`. `fetch`/`import-platform` additionally exit non-zero for a
missing `--spki-pin`, an invalid `--purpose`, and (`import-platform` only) an
empty host:port argument.

A pin or DANE mismatch is the one to stop on rather than retry with `--method
direct`.

## Parity coverage

The `go-xkms` parity runner covers `xkmsctl`. Bootstrap itself is covered by
`go-xkms/pkg/trust/bootstrap/*_test.go` and
`go-xkms/test/integration/bootstrap`; `fetch`/`import-platform` are covered by
`pkg/trust/fetcher/*_test.go` (the HTTP/TLS/pin layer) and
`xkey/cmd/xkey/cmd/trust_fetch_test.go` (the CLI flag and dispatch layer, over
an `httptest.Server`); xkey's remaining own coverage is the truststore and NSS
suites.
