# Attestation Verifier — User Guide

> **Status: NORMATIVE** · Feature: `attestation-verifier` · Module: `go-xkms` · Last verified: 2026-09-25

## What this is for

Requiring that a certificate request prove, cryptographically, that its key
lives in a specific vendor's hardware — a YubiKey, a TPM 2.0 chip, an Android
device's StrongBox — before `xkmsd` signs it. Without this configured,
attestation-gated issuance is off: nothing checks where a CSR's key actually
lives.

This is an operator-facing, config-only feature. There is no CLI verb and no
end-user workflow — see [`cli.md`](cli.md) if you were looking for one.

## Turning it on

Add an `attestation:` block to the xkmsd config, naming, per format, the root
certificates you trust to have issued that vendor's device certificates:

```yaml
attestation:
  formats:
    tpm2:
      external_root_paths:
        - /etc/xkms/tpm-manufacturer-root.pem
    yubikey-piv:
      external_root_paths:
        - /etc/xkms/yubico-piv-root.pem
    android-key-attestation:
      embedded_roots:
        - google-hardware-attestation
```

Restart `xkmsd`. On startup it logs which formats were wired:

```
Hardware attestation trust anchors wired  formats=[tpm2 yubikey-piv android-key-attestation]
```

A format you did not list here is refused at issuance time, not silently
accepted — a client that submits an attestation chain for a format you never
configured gets an explicit "not configured" error, not a certificate.

A **broken** configuration — a path that does not exist, a PEM that does not
parse, or a format left with zero resulting roots — is **fatal at startup**,
not a runtime surprise discovered under load. Fix the config and restart;
there is no partial-service mode where some formats work and others silently
do not.

## What "attestation-gated" actually checks

Two things, both required:

1. **The evidence traces to a root you configured for that format.** A TPM
   chain has to terminate at the TPM manufacturer root you named; a PIV
   chain at the Yubico root; an Android chain at Google's Hardware
   Attestation root (or your own, if you supplied one instead of the
   embedded default).
2. **The evidence is actually about the key being certified**, not just
   "some hardware, somewhere." A caller cannot present a genuine chain
   captured from a different device or a different key and have it certify
   theirs.

Both matter. The first without the second would let anyone holding *any*
valid attestation chain — these are not secret, they travel with every
enrollment — attach it to a CSR for a key they generated in plain software
and receive a certificate that reads as hardware-backed to every relying
party that checks it.

## The one escape hatch, and why you probably don't want it

A format can, in principle, present evidence this server has no way to check
for key binding — not "the binding failed," but "there is no mechanism here
to check it at all." Refusing those requests is the default. An embedder can
call `AllowUnboundAttestationFormats(true)` to accept them anyway — there is
no config key or CLI flag for this, only a Go API a server binary can call —
and every certificate issued that way is logged at `WARN` stating plainly
that it asserts hardware backing this server did not establish. Turning it on
is a decision to accept that gap for a specific deployment; it does not widen
any other check. Key binding and challenge freshness stay enforced no matter
what.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| server fails to start after adding `attestation:` | a bad path, unparseable PEM, or a format with zero roots | check the exact path/PEM named in the startup error; `AttestationConfig.Verifiers()` refuses to build an anchorless verifier |
| a CSR with an attestation chain is refused, "not configured" | the format on the request has no matching entry under `attestation.formats` | add it, or confirm the client sent the format string you expect (matching is case-insensitive) |
| a genuine device's CSR is refused, chain does not anchor | the configured root does not match the device's actual issuer, or the wrong root was pasted in | re-check the vendor root against the device's own chain |
| a genuine device's CSR is refused, "key not bound" | the attestation chain does not attest to the key in this specific CSR | the client attached the wrong chain, or an old one; regenerate the attestation for this key |
| a genuine device's CSR is refused, "challenge does not match" | the evidence carries a different (or no) challenge than the one this server expects | for formats with a challenge mechanism, confirm the client used the nonce the server actually issued |
| TCG-CSR-IDEVID enrollment fails at the same kind of check | the TCG carrier calls this same gate for the TPM2 format — same causes, different route (`SignTCGCSR`, not `SignCSR`) | see [`../certificate-authority/user.md`](../certificate-authority/user.md) for the TCG enrollment ceremony itself |

## Where to go next

- The CSR route this gates, and its error responses on the wire:
  [`../certificate-authority/api.md`](../certificate-authority/api.md)
- Generating an attestation to submit in the first place:
  [`../key-management/cli.md`](../key-management/cli.md) (`xkmsctl key
  attest`), [`../tpm2/user.md`](../tpm2/user.md),
  [`../pkcs11-backend/user.md`](../pkcs11-backend/user.md)
- TPM manufacturer/EK trust for the TCG-CSR-IDEVID enrollment ceremony
  specifically (a separate anchor set from this feature's):
  [`../certificate-authority/engineering.md`](../certificate-authority/engineering.md)
- Verifying that a *live TLS peer* is currently attested, a different
  question from CSR issuance: [`../attested-peer/user.md`](../attested-peer/user.md)
