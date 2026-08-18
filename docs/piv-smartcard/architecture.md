# PIV Smartcard — Architecture

> **Status: NORMATIVE** · Feature: `piv-smartcard` · Repo: `go-xkms` · Last verified: 2026-08-19

## The problem

PIV (NIST SP 800-73-4) is the credential model that federal and enterprise
deployments already have: a card with numbered slots, each holding a key and a
certificate for a specific purpose. Supporting it means supporting the *slot
model*, not just "a key on a card" — code that treats a PIV card as a generic
key store gets the purposes wrong and breaks interoperability with everything
else that reads the card.

The second problem is that the slot model is useful even when there is no card.
The same numbered-purpose structure is what you want in a TPM, or a PKCS#11
token, or a file — so this feature makes the *storage* pluggable and keeps the
slot semantics fixed.

## Shape chosen: fixed slot semantics, pluggable storage

`pkg/pivcert` defines the slot vocabulary as a closed set of typed constants
(`PIVSlot`, a string):

| Slot | Constant | Purpose |
|---|---|---|
| `9a` | `PIVSlotAuthentication` | PIV card and cardholder authentication |
| `9c` | `PIVSlotDigitalSignature` | document signing, non-repudiation |
| `9d` | `PIVSlotKeyManagement` | key establishment and transport |
| `9e` | `PIVSlotCardAuthentication` | card authentication without cardholder interaction |
| `f9` | `PIVSlotAttestation` | device attestation certificate proving key origin (YubiKey-compatible) |
| `82`–`95` | `PIVSlotRetired1`…`PIVSlotRetired20` | historical key-management certificates, for decrypting old data |

`AllSlots()`, `PrimarySlots()` and `RetiredSlots()` return these sets;
`ValidateSlot(slot)` rejects anything else. A slot is never an arbitrary string.

Storage is chosen independently (`PIVStorageType`):

| Type | Constant | Backing |
|---|---|---|
| `file` | `StorageTypeFile` | file system (`pkg/pivcert/file`) |
| `tpm2` | `StorageTypeTPM2` | TPM2 NV storage (`pkg/pivcert/tpm2`) |
| `pkcs11` | `StorageTypePKCS11` | PKCS#11 token objects (`pkg/pivcert/pkcs11`) |

`IsValid()` closes that set too. The seams are two interfaces:
`PIVCertificateStorage` (put/get/delete a certificate in a slot) and
`PIVSlotRegistry` (enumerate and describe slots).

Rejected alternatives:

- **Treating a PIV card as a generic PKCS#11 token.** Rejected: it loses the
  slot purposes, and a certificate in the wrong slot is rejected by every other
  PIV consumer.
- **Slots as free-form strings.** Rejected: `ValidateSlot` catching `"9f"` at
  the boundary is worth more than a runtime failure inside a card.
- **A separate implementation per storage type.** Rejected — that is three
  copies of the slot model.

## Component boundaries

| Piece | Package |
|---|---|
| Slot model, storage types, config, errors | `pkg/pivcert/pivcert.go` |
| Slot occupancy / registry model | `pkg/pivcert/slotmodel.go`, `slotinfo.go` |
| Chain verification and thumbprints | `pkg/pivcert/verify.go` |
| File storage | `pkg/pivcert/file` |
| TPM2 NV storage | `pkg/pivcert/tpm2` |
| PKCS#11 storage | `pkg/pivcert/pkcs11` |
| Key generation / operations in the keystore | `pkg/xkms/piv_*.go` (`piv_manager.go`, `piv_ops.go`, `piv_keygen_backend.go`, `piv_keygen_software.go`) |
| Wire surface | `pkg/api/rest/handlers_piv.go`, `pkg/api/grpc`, `pkg/api/mcp/handlers_piv.go` |
| The PIV auth factor | `pkg/factor/piv` — [`../auth-factors/`](../auth-factors/architecture.md) |

PIV is named in go-xkms's ownership statement alongside WebAuthn and FIDO2; the
PIV *factor* is capability row **"FIDO2 / PIV / PKCS#11 factor impls" (tier 2)**,
and the SDK reaches it as `Security().Auth().PIV()`.

## The retired-slot preference, and why it exists

`slotmodel.go` records a non-obvious rule: when allocating, the model **prefers
retired slots (82–95) over primary slots (9a–9e), to preserve standard PIV slot
semantics**. A tool that grabbed `9a` for an arbitrary key would break card
authentication for everything else that reads the card. Retired slots exist for
exactly this — holding keys that are not one of the four standard purposes.

## Data flow

```
generate:
  xkmsctl piv generate 9a --algorithm ecdsap256 --subject "CN=alice"
    → PIVSlotRegistry validates the slot
    → key generation: hardware generator (PKCS#11 / TPM2) or software
    → certificate stored via PIVCertificateStorage into {file | tpm2 NV | pkcs11}

use:
  CSR:    xkmsctl piv csr 9a  →  CSR signed by the slot's key
  export: xkmsctl piv export 9a  →  the certificate (never the private key)
  auth:   pkg/factor/piv  →  challenge signed by the slot's key
```

TPM2 storage maps each slot to an NV index — `GetNVIndex(slot, baseIndex)`
computes it from a configured base, so a deployment controls where in NV space
its PIV data lives.

## Trust boundaries

- **A slot is a purpose, not a container.** Putting a signing key in `9e` makes
  it usable without cardholder interaction, which is a real difference in
  authority.
- **The private key never leaves.** `piv export` exports the *certificate*.
- **`f9` attestation is only as good as its chain.** An attestation certificate
  is evidence about key origin; verify it (`VerifyChain`) rather than trusting
  its presence.
- **Software PIV proves possession of a key, not of a card.** With no hardware
  generator configured (`piv_keygen_software.go`), the slot model is real and
  the hardware guarantee is not. See
  [`../auth-factors/architecture.md`](../auth-factors/architecture.md).
- **TPM2 NV space is finite and shared.** A misconfigured base index can collide
  with something else in NV.

## What this feature deliberately does not do

- **It does not implement a PIV applet.** It reads and writes PIV-shaped
  credentials; it is not a card operating system.
- **It does not own the PIN.** Card PINs are
  [`../pin-management/`](../pin-management/architecture.md).
- **It does not decide authentication.** The PIV factor answers a challenge;
  go-qrdb decides.
- **It does not issue the certificates.** That is
  [`../certificate-authority/`](../certificate-authority/architecture.md) — PIV
  produces the CSR.
