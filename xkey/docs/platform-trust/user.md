# Platform Trust — User Guide

> **Status: NORMATIVE** · Feature: `platform-trust` · Module: `go-xkms/xkey` · Last verified: 2026-09-29

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

Against a platform instance where you already have a SPKI pin — obtained
out-of-band, never from the connection you are about to make — the one-liner:

```
xkey trust import-platform kms.example.com:8443 \
  --spki-pin 3a7be5f1c0baf12c3d9e6a1b8f4c2d0e5a9b7c3f1e8d6a4b2c0f9e7d5c3b1a9f \
  --install-system
```

`--spki-pin` is **required** — there is no shorter form that skips it. That
fetches the bundle over pinned TLS. **It does not trust on first use** — if
the pin does not verify, nothing is stored, and that is the feature working:

```
$ xkey trust import-platform kms.example.com:8443
Error: trust: invalid fetch arguments: --spki-pin is required (no trust-on-first-use path)
```

`import-platform` is a shorthand for `xkey trust fetch` against the canonical
`https://<host:port>/v1/ca/bootstrap` URL. Use `fetch` directly when the
bundle lives somewhere else:

```
xkey trust fetch https://kms.example.com:8443/v1/ca/bootstrap \
  --spki-pin 3a7be5f1c0baf12c3d9e6a1b8f4c2d0e5a9b7c3f1e8d6a4b2c0f9e7d5c3b1a9f
```

Where do you get the pin? See "Getting a SPKI pin", below — it is never a
value pasted from the page you are trying to verify.

## Getting a SPKI pin

The SPKI hash passed to `--spki-pin` MUST come from a channel that does not
depend on the very TLS connection it verifies. That rules out anything you
read from the site itself. Acceptable sources:

- A deployment manifest cryptographically bound to the node's identity at
  provisioning time (for example, HSM-attested).
- A signed deploy log written to persistent, authenticated storage.
- A value transcribed from the server's own console at first boot.
- A provisioning artifact an operator authored and delivered through a
  trusted secure-distribution channel.

A hash copied from an HTTP page, a chat message, or any other unauthenticated
source defeats the entire point of pinning — an attacker in front of you can
hand you *their* pin just as easily as the real one. If you cannot get the
hash this way, use `xkey trust bootstrap` (DNSSEC/DANE, or a pre-shared
truststrap manifest) or `xkey trust add` (manual PEM import after a secure
file transfer) instead.

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
| `synced` | nothing — received from a paired device by sync, quarantined until reclassified |

A certificate a paired phone sent during sync shows up as `synced`. It is
stored so you can see it, not trusted: check it, then `xkey trust classify` it
if you want it to anchor anything.

`xkey trust add` without `--purpose` guesses, and the guess never makes a
certificate `android-hardware` unless it is one of the Google Hardware
Attestation Roots built into xkey. To trust another Android attestation root,
say so: `xkey trust classify <fingerprint> --purpose android-hardware`.

`xkey backup restore` puts every certificate back under the purpose it had
when it was backed up. A backup whose trust-store entry has no purpose, or one
this version does not know, is refused rather than guessed at — re-create it.

**This is enforcement, not filing.** A `general` certificate will not anchor a
TPM attestation. When an attestation fails, the fix is to add the right
manufacturer anchor — not to reclassify something you already have as
`tpm-manufacturer` so it passes. Doing that removes the exact guarantee
attestation was providing.

## Making the system trust it too

```
xkey trust install <fingerprint>
xkey trust uninstall <fingerprint>
```

`install` writes into your **operating system and browser (NSS) trust stores**.
After it, every application on the machine trusts that certificate — not just
xkey. That is usually what you want, and it is worth knowing you did it:
removing xkey later does not undo it. `uninstall` does.

`xkey trust import-platform --install-system` runs the fetch and this install
step together, for any self-signed root certificate the bundle contains — see
"Getting the bundle", above.

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
xkey trust install <fingerprint>
```

Or, given a pin instead of a truststrap configuration:

```
xkey trust import-platform kms.example.com:8443 --spki-pin <hex> --install-system
xkey trust list -o json
```

A fetched bundle — from either command, or from the GUI's trust-strap import —
is already filed as `bootstrap-ca`. Classify only to give it another purpose.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| SPKI pin mismatch | the server did not verify | **stop.** Confirm the pin out of band; do not switch to `--method direct` |
| `fetch`/`import-platform` refuses to run at all | `--spki-pin` was omitted or blank | pass it — there is no unpinned mode |
| `import-platform` error starts with `trust: import-platform failed:` | the underlying `fetch` failed | read past the prefix — the wrapped cause (bad pin, unreachable host, HTTP error) is the fix |
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
- Launching a browser that already trusts what you just imported:
  [`../browser-trust-injection/user.md`](../browser-trust-injection/user.md)
- Logging in once the browser (or the CLI itself) trusts the server:
  [`../headless-webauthn/user.md`](../headless-webauthn/user.md)
