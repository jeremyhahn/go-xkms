# Platform Trust — User Guide

> **Status: NORMATIVE** · Feature: `platform-trust` · Module: `go-xkms/xkey` · Last verified: 2026-08-19

## What this is for

Getting the platform's CA bundle onto your machine, safely, and being explicit
about what each certificate is trusted *for*.

## Getting the bundle

```
xkey trust bootstrap --method dane,spki --timeout 60s
```

Each method anchors on something you already have: DANE on DNSSEC, `spki` on a
pin someone gave you out of band, `noise` on a public key given the same way.
`direct` trusts the public web PKI and checks nothing else — it is the
last-resort option.

Against a platform instance, the one-liner:

```
xkey trust import-platform kms.example.com:8443
```

That fetches the bundle over pinned TLS. **It does not trust on first use** — if
the pin does not verify, nothing is stored, and that is the feature working.

## Say what each certificate is for

```
xkey trust list -o json
xkey trust classify <fingerprint> --purpose bootstrap-ca
```

| Purpose | Trusted for |
|---|---|
| `general` | ordinary TLS |
| `tpm-manufacturer` | anchoring TPM endorsement keys |
| `android-hardware` | anchoring Android hardware attestation |
| `user-ca` | user and client certificates |
| `bootstrap-ca` | the trust-bootstrap path |
| `idevid-issuer` | IDevID issuance |

**This is enforcement, not filing.** A `general` certificate will not anchor a
TPM attestation. When an attestation fails, the fix is to add the right
manufacturer anchor — not to reclassify something you already have as
`tpm-manufacturer` so it passes. Doing that removes the exact guarantee
attestation was providing.

## Making the system trust it too

```
xkey trust install <fingerprint>
xkey trust test
xkey trust uninstall <fingerprint>
```

`install` writes into your **operating system and browser (NSS) trust stores**.
After it, every application on the machine trusts that certificate — not just
xkey. That is usually what you want, and it is worth knowing you did it:
removing xkey later does not undo it. `uninstall` does.

`trust test` checks that the store validates what it should. Run it after any
change.

## Adding one by hand

```
xkey trust add platform-ca.pem --purpose bootstrap-ca --source file:platform-ca.pem
xkey trust show <fingerprint> -o json
xkey trust remove <fingerprint>
```

`--source` records where it came from — `manual`, `url:…`, `file:…`. In six
months it is the only thing that will tell you why an anchor is there.

Everything after `add` uses the **fingerprint**, not a name. Names can be chosen
by whoever issued the certificate; fingerprints cannot.

## A first run

```
xkey trust bootstrap --method spki --timeout 60s
xkey trust list -o json
xkey trust classify <fingerprint> --purpose bootstrap-ca
xkey trust install <fingerprint>
xkey trust test
```

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| SPKI pin mismatch | the server did not verify | **stop.** Confirm the pin out of band; do not switch to `--method direct` |
| DANE fails but the record looks right | no DNSSEC validation on your resolver | use a validating resolver |
| bootstrap "did nothing" | no method was configured | a typo in `--method` silently skips |
| a TPM attestation is rejected | the manufacturer anchor is missing or misclassified | add the right anchor; do not reclassify an unrelated one |
| the browser still does not trust it | classified but not installed | `xkey trust install <fingerprint>` |
| a certificate is still trusted after removing xkey | `install` wrote to the system store | `xkey trust uninstall` before removing |
| `classify` refuses to run | `--purpose` is required | pass it deliberately |

## Where to go next

- What each bootstrap method anchors on: [`../../../docs/trust-bootstrap/user.md`](../../../docs/trust-bootstrap/user.md)
- The CA serving the bundle: [`../../../docs/certificate-authority/user.md`](../../../docs/certificate-authority/user.md)
- What TPM anchors are used for: [`../../../docs/tpm2/user.md`](../../../docs/tpm2/user.md)
