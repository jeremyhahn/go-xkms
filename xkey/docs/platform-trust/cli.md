# Platform Trust — CLI

> **Status: NORMATIVE** · Feature: `platform-trust` · Module: `go-xkms/xkey` · Last verified: 2026-08-19

Binary: `xkey`, group `trust` (`xkey/cmd/xkey/cmd/trust.go`).

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

## `xkey trust import-platform <host:port>`

```
xkey trust import-platform kms.example.com:8443
```

Fetches the platform's CA bundle over **SPKI-pinned TLS** and imports it. **No
trust on first use** — if the pin does not verify, nothing is stored.

## `xkey trust fetch <url>` / `add` / `list` / `show` / `remove`

| Verb | Flags |
|---|---|
| `trust fetch <url>` | — |
| `trust add <pem-file>` | `--purpose`, `--source` |
| `trust list` | — |
| `trust show <fingerprint>` | — |
| `trust remove <fingerprint>` | — |

```
xkey trust add platform-ca.pem --purpose bootstrap-ca --source file:platform-ca.pem
xkey trust list -o json
xkey trust show 3fa1…  -o json
```

`--source` records where the certificate came from (`manual`, `url:…`,
`file:…`). It is the only provenance you will have later.

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

```
xkey trust classify 3fa1… --purpose tpm-manufacturer
```

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

## `xkey trust test`

```
xkey trust test
```

Verifies that the store validates what it should. Worth running after any
`classify` or `install`.

## A first-run sequence

```
xkey trust bootstrap --method spki --timeout 60s
xkey trust list -o json
xkey trust classify <fingerprint> --purpose bootstrap-ca
xkey trust install <fingerprint>
xkey trust test
```

## Exit codes

`0` on success. Non-zero for an SPKI mismatch, a DANE record that does not
validate, a Noise key mismatch, an unknown fingerprint, or a missing
`--purpose`.

A pin or DANE mismatch is the one to stop on rather than retry with `--method
direct`.

## Parity coverage

The `go-xkms` parity runner covers `xkmsctl`. Bootstrap itself is covered by
`go-xkms/pkg/trust/bootstrap/*_test.go` and
`go-xkms/test/integration/bootstrap`; xkey's own coverage is the truststore and
NSS suites.
