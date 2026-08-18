# Certificate Authority — User Guide

> **Status: NORMATIVE** · Feature: `certificate-authority` · Repo: `go-xkms` · Last verified: 2026-08-19

## Prerequisites

- A running `xkmsd` with a CA configured, and an authenticated session
  (`--token`, or client certificates).
- If you want the CA's signing key in hardware, that backend configured on the
  **server** — the choice is made at CA creation and cannot be changed later
  without a new CA.

If `ca` verbs report the CA as unavailable, this server has no CA configured.
That is a server-side change, not something the client can fix.

## First: get the trust bundle

Everything else depends on the client trusting the CA.

```
xkmsctl --server https://kms.example.com:8443 ca bundle > ca-bundle.pem
```

If you do not yet trust the server enough to run that command, use the trust
bootstrap path instead — DANE, an SPKI pin, or Noise — which verifies the bundle
out of band. See [`../trust-bootstrap/user.md`](../trust-bootstrap/user.md).
Fetching a bundle over an unverified connection and trusting it is the one
mistake this whole subsystem exists to prevent.

## Issue a certificate

Two ways, depending on where the private key should be generated.

**You already have a key and a CSR** — the key never moves:

```
xkmsctl ca sign-csr --csr node.csr --profile server --validity 90 --output node.crt
```

**You want the service to make both:**

```
xkmsctl ca issue --cn gateway.example.com --profile server \
    --sans DNS:gateway.example.com,DNS:gw.example.com \
    --algorithm ecdsa-p256 --validity 90 --output gateway.crt
```

`--profile` picks the extension set — `server`, `client`, and whatever else this
CA is configured with. Getting it wrong produces a certificate that validates
but is rejected for the wrong extended key usage, which is a confusing failure;
check the profile first.

`--validity 0` (the default) means "use the CA's default", which is usually what
you want. A validity longer than the issuer's remaining lifetime will not help
you — chains fail when the issuer expires.

## Check and revoke

```
xkmsctl ca status --serial 0a1b2c3d4e5f
xkmsctl ca revoke --serial 0a1b2c3d4e5f --reason 1
xkmsctl ca crl --output current.crl
```

Reason codes are RFC 5280's; `1` is `keyCompromise`, `0` is unspecified.
Revocation is not retroactive to anything already trusting the certificate —
publish the fresh CRL where relying parties actually read it, or revocation has
no effect in practice.

## Store a certificate against a key

Issuance and storage are separate. If you issued elsewhere and want the
certificate kept with its key:

```
xkmsctl cert save web-tls web.crt
xkmsctl cert save-chain web-tls web.crt intermediate.crt
xkmsctl cert get-chain web-tls > web-chain.pem
xkmsctl tls get web-tls -o json
```

`tls get` is what a server process asks for at startup: the certificate plus
whatever the key backend needs to use the private key.

## Enrolling a device with a TPM

For hardware whose identity is a TPM endorsement key, the flow is EK
certificate → AK certificate → device enrollment, all under `ca tcg` on the
API side. The evidence is stored with the CA and can be verified later. Details
and the attestation semantics are in
[`../tpm2/user.md`](../tpm2/user.md).

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| CA verbs return "not implemented" | no CA configured on this server | server-side configuration |
| "not initialized" | the CA exists in config but was never created | run the init ceremony |
| certificate validates locally but peers reject it | wrong profile, or the peer got an unfiltered bundle | re-issue with the right `--profile`; for mixed-algorithm CAs give the peer the filtered bundle |
| chain building fails on the far end | the peer does not have the intermediate | ship the chain, not just the leaf |
| revocation "worked" but clients still accept the certificate | the CRL you generated is not where clients look | publish the new CRL |
| serial not found | wrong serial format | hex, no `0x`, no colons |

## Where to go next

- Automated issuance and renewal: [`../acme-issuance/user.md`](../acme-issuance/user.md)
- Trusting a server you have never met: [`../trust-bootstrap/user.md`](../trust-bootstrap/user.md)
- Putting the CA key in a TPM or HSM: [`../crypto-backends/user.md`](../crypto-backends/user.md)
