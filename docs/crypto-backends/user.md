# Crypto Backends — User Guide

> **Status: NORMATIVE** · Feature: `crypto-backends` · Repo: `go-xkms` · Last verified: 2026-10-11

## Which backend should I use?

| If you want… | Use | Because |
|---|---|---|
| to get started, or to run in CI | `software` | no hardware, no accounts, works everywhere |
| keys that physically cannot leave the machine | `tpm2` | keys can be marked fixed to the TPM, and can be attested |
| an HSM or smartcard you already own | `pkcs11` | any Cryptoki token, including Nitrokey HSM |
| keys managed by your cloud provider | `awskms`, `gcpkms`, `azurekv` | the provider's HSM holds the material |
| HashiCorp Vault as the key service | `vault` | transit engine |
| post-quantum signatures or encapsulation | `quantum` | ML-DSA, ML-KEM |
| a signing key split across several holders | `frost` | threshold signatures; see the FROST guide |
| your phone as the secure element | `phone` | TEE/StrongBox via the xkey pairing protocol |
| an AVR device whose identity lives in a secure element | `avr` | read-only: the device's public identity, DICE attestation, and what it says about its own root of trust |

## Before you commit to one

Ask the server what it actually has, and what that backend can actually do:

```
xkmsctl backends list
xkmsctl backends get tpm2 -o json
```

The second command is the one that matters. Two deployments can both offer
`pkcs11` and disagree about whether export is allowed, because the token's own
policy is stricter than the software's ceiling. Read the capability block rather
than assuming.

The capabilities you will care about most:

- **`HardwareBacked`** — is the private key outside this process?
- **`Export`** — can you ever get the material back out? On Azure Key Vault the
  answer is no, even though import works.
- **`Attestation`** — can this backend prove where a key was made?
- **`Sealing`** — can it protect arbitrary data with its own mechanism?

## Prerequisites per backend

- **software / pkcs8** — a writable key directory (`--key-dir`).
- **tpm2** — a TPM present, or the simulator for development. The simulator
  serves one client at a time; two test runs against the same simulator will
  block each other.
- **pkcs11** — the token's Cryptoki `.so`, the slot number, and the user PIN.
  Set the security-officer PIN before the user PIN on a fresh token.
- **cloud (awskms / gcpkms / azurekv / vault)** — credentials in the
  **server's** environment. You never pass these on the command line.
- **phone** — a paired xkey-android device.
- **avr** — a device running arduino-generic firmware, on a serial link the
  caller opens. There is no credential: the link is the access.

## "That backend is not compiled in"

Every backend is compiled in by default. A build can leave one out with its
`WITH_*` toggle set to `0`: `WITH_PKCS11`, `WITH_AWS_KMS`, `WITH_GCP_KMS`,
`WITH_AZURE_KV`, `WITH_VAULT`, `WITH_FROST`. The `software`, `pkcs8`, `tpm2` and
`quantum` backends are always compiled; `WITH_TPM2` only affects the TPM slot
of the PKCS#11 provider module. `avr` is never loaded from configuration: an
application opens it directly over the device's serial link.

If you configure a backend the binary does not have:

- **`xkmsd`** logs `… backend enabled in config but not compiled in` and
  starts without it; a configured `frost` backend stops the server instead.
- **An application using the SDK** (`xkms.AutoInitialize`) refuses to start
  with an error such as
  `xkms: backend "vault" is not compiled into this binary; build with WITH_VAULT=1 (build tag "vault")`.

Rebuild with the toggle on rather than falling back — a build that quietly
used software instead would put your keys somewhere you did not choose.

```
make build-full          # every feature on
xkmsctl backends list    # tells you what the server really has
```

## Moving a key between backends

```
xkmsctl key copy web-tls web-tls-cloud --dest-backend awskms
```

This only works when the source key is exportable and the destination supports
import. A TPM key marked fixed cannot be copied anywhere, ever — that is the
guarantee you bought.

## Troubleshooting

| What you see | What it means |
|---|---|
| backend missing from `backends list`, or `not compiled into this binary` | compiled out; rebuild with its `WITH_*` toggle on |
| `resolving key storage for backend …` | the SDK could not derive that backend's key storage from the datastore; fix the datastore, the backend is not skipped |
| `security officer PIN required` | fresh token — set the SO PIN, then the user PIN |
| `user PIN required` | the token has no user PIN yet, or it is not unlocked; see the PIN guide |
| export refused on Azure Key Vault | expected — it supports import and not export |
| operations hang against the TPM simulator | another process holds the single simulator connection |
| a cloud backend fails with credentials errors | fix the **server's** environment, not the client's |

## Where to go next

- Doing things with the keys: [`../key-management/user.md`](../key-management/user.md)
- Hardware sealing and PCR policies: [`../tpm2/user.md`](../tpm2/user.md)
- Token PINs and lockout: [`../pin-management/user.md`](../pin-management/user.md)
