# PIV Smartcard — Architecture

> **Status: NORMATIVE** · Feature: `piv-smartcard` · Repo: `go-xkms` · Last verified: 2026-09-21

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
  is evidence about key origin; verify it (`VerifyAttestation`) rather than
  trusting its presence.
- **A verified chain is not a satisfied policy.** Verification establishes that
  the attestation anchors to a root the caller trusts. It says nothing about
  what the certificate claims — a trusted chain may carry no readable evidence
  at all. Read the decoded claim, do not infer it from a nil error.
- **Attestation over an imported key asserts residency, not exclusivity.**
  This is the sharpest limit on what a PIV attestation is worth, and it is not
  visible in the attestation itself. See below.
- **Software PIV proves possession of a key, not of a card.** With no hardware
  generator configured (`piv_keygen_software.go`), the slot model is real and
  the hardware guarantee is not. See
  [`../auth-factors/architecture.md`](../auth-factors/architecture.md).
- **TPM2 NV space is finite and shared.** A misconfigured base index can collide
  with something else in NV.

## Two classes of key live in a slot

`ImportPIVKey` places an externally held private key in a slot. That makes a
slot's contents one of two things, and **an attestation cannot tell you which**:

| How the key got there | What the slot can prove | What it cannot prove |
|---|---|---|
| generated in-slot | the key is in this slot | — |
| imported | the key is in this slot | that it is *only* here |

A slot-generated key cannot have existed anywhere before it existed in the
slot: there was no earlier copy to retain. An imported key can, and nothing
about the slot afterwards distinguishes a key that was only ever there from one
whose original is still sitting in the file it was read from. The card signs
identically either way, and the attestation certificate says the same thing in
both cases.

So a verifier that reads "attested" as "generated in-slot, therefore unique"
is drawing a conclusion the evidence stopped supporting the moment import
became possible. Residency is attested. **Exclusivity is not**, and no amount
of chain verification recovers it — `VerifyChain` anchors the attestation to a
manufacturer, which says the card is genuine, not that the key was born on it.

The practical consequences:

- **Non-repudiation weakens.** A signature from an imported key does not
  establish that only the cardholder could have produced it, because the
  original key may still exist elsewhere.
- **"One key, one card" stops holding.** The same imported key may be in
  several slots, on several cards, or in none of them and still in a file.
- **The limitation is invisible on the wire.** Nothing in a PIV attestation
  today carries the distinction, so a relying party cannot ask for it. A
  deployment that needs exclusivity must obtain it out of band — by generating
  in-slot and never importing — rather than by inspecting an attestation.

**If you need exclusivity, generate in-slot.** `GeneratePIVKey` is the only
operation that establishes it, and it establishes it by construction rather
than by assertion. Import exists for keys whose provenance is already
established elsewhere — migrating an existing identity onto a card, or loading
a key a CA issued — where the caller has already decided that residency is the
property they need.

## Reading an attestation back

xkms emitted attestation material that nothing in the stack could decode: a
consumer could establish that a chain anchored, and nothing about the device or
the policy governing the key. `pkg/pivcert` now parses the vendor extensions —
firmware version, serial number, PIN and touch policy, form factor — so a
deployment can enforce *"touch must be required"* or *"this serial is on the
allowlist"* rather than only *"something attested"*.

Three properties shape it:

- **Parsing and trusting are separate.** `ParseAttestation` evaluates no trust;
  `VerifyAttestation` anchors a chain against roots the **caller** supplies.
  This package ships no vendor root, because which root a deployment trusts is
  its decision. A deployment with none configured keeps the presence check it
  already has instead of choosing between a full verdict and none.
- **Absent and unparseable are different answers.** A device that does not
  report a touch policy is not the same as one whose touch policy could not be
  decoded; the first may be acceptable, the second means the evidence is not
  understood. They are reported distinctly, and a value that decodes but is
  unknown to this build is a third thing again.
- **Unreadable beats wrongly read.** The layout is Yubico's documented one and
  has not been checked against a physical device, so decoding is strict and a
  mismatch is reported rather than coerced. A caller can handle "I could not
  read this"; it cannot handle a confidently wrong touch policy. See
  [`engineering.md`](engineering.md) for the scope of that limitation.

## An imported key is not attestable

The table above describes what an attestation *would* mean. xKey does not issue
one: **`AttestPIV` refuses a slot whose key arrived by import**, returning
`ErrPIVKeyImportedNotAttestable`.

The refusal exists because the alternative is an attestation that asserts less
than the verifier reads, with nothing on the wire to say so. Two reasons decide
the design:

- **It matches the hardware.** YubiKey PIV attestation is already available
  only for slot-generated keys; importing makes a slot unattestable there. If
  xkms attested imported keys, an xkms PIV attestation would assert something
  weaker than a YubiKey one *while looking identical to a verifier* — an
  invisible difference at the moment it matters most.
- **It is derived from provenance, not configuration.** A configuration switch
  would be mutable state: it can be flipped after the key lands, and it creates
  an ordering hazard where configuring for attestation and then importing
  forces one of the two to lose. "This key was imported" is decided once, by
  the code path that placed the key, and can never become false.

### How provenance is recorded

`types.KeyOrigin` (`generated` / `imported`) is stamped on the key's own
attributes by the code path that ran and persisted with the key record. It is
**never accepted from a caller** — the generate and import paths strip and
recompute it, the same rule PKCS#11 applies to `CKA_LOCAL`, whose template
handling removes token-computed attributes so a caller cannot forge provenance.
A provenance field a caller could set would be worse than none, because a
verifier would read it as authoritative when it is merely asserted.

`KeyOrigin` is a sibling axis to where the key lives, not the same one. A
hardware-resident key may still have been imported, and that combination is
the dangerous one: trusted-looking on every other axis, lacking exactly the
property attestation is taken to prove.

### AttestLevel: KeyOrigin's sibling, not its replacement (#220)

`KeyOrigin` answers *how* a key arrived. It does not answer *where it lives*
— and #207's own design note is explicit that the two must stay separate
fields: folding "hardware" into the origin vocabulary would make an imported
hardware key carry the vocabulary's most trusted value while lacking
exclusivity entirely, exactly the case a verifier most needs to tell apart.

`types.AttestLevel` (`pkg/types`, alongside `KeyOrigin`) is that second axis:
`AttestLevelHardware`, `AttestLevelSoftware`, or `AttestLevelUnattested`. It
is the one vocabulary shared with go-quicbaas's `AttestLevel`
(go-quicbaas#379) — the ownership ruling on #220 put xkms in charge of the
spelling, so a composed node never translates between two enumerations that
mean the same fact.

`types.KeyAttributes.AttestLevel` is recorded next to `KeyOrigin`, at the
same enrollment-time write: both `backendPIVKeyGenerator.GeneratePIVKey` and
`.ImportPIVKey` stamp it before the key reaches the backend. The value comes
from `PIVAttestLevelReporter`, an optional `PIVKeyGenerator` capability
mirroring `PIVKeyOriginReporter`'s shape:

```go
type PIVAttestLevelReporter interface {
    AttestLevel(slot pivcert.PIVSlot, cn string) (types.AttestLevel, error)
}
```

Unlike `PIVKeyOrigin`, this is not a per-key persisted-record lookup — a
backend's hardware backing does not vary key to key, so the answer is a
property of the *generator*, read live from
`types.Capabilities.HardwareBacked` (`backend.KeyProvider().Capabilities()`),
the same signal the backend catalog already uses to describe a backend's
trust class. `backendPIVKeyGenerator` reports `Hardware` when the underlying
backend is hardware-backed and `Software` otherwise; the fallback
`softwarePIVKeyGenerator` always reports `Software`. A `PIVKeyGenerator` with
no `PIVAttestLevelReporter` at all — the shape of a caller-supplied generator
that cannot back any claim about its hardware backing — resolves to
`AttestLevelUnattested` through `pivAttestLevel`, the same "absent capability
fails to the weakest claim" rule `PIVKeyOriginReporter`'s absence follows.

`pkg/keyprovider/pkcs8` needs no metadata round trip for this field, unlike
`KeyOrigin`: PKCS#8 storage is software cryptography by construction, so
`ListKeys` always reports `AttestLevelSoftware` for a key it holds, overriding
whatever was stamped in memory — the same "computed by the system, never
trusted from a caller" rule `KeyOrigin` follows, applied even more strongly
because there is no legitimate case where this backend answers `Hardware`.

### The origin rule, and where it lives

Attestation **fails closed on the origin**: anything that is not `generated` is
refused, except `unknown` -- see below. It does not refuse only the values
known to be bad, because a check shaped that way would start attesting
silently the day a new write path forgot to record an origin — nothing would
fail, and nothing would warn.

`resolveKeyOrigin` in `pkg/keyprovider/pkcs8` is a plain read of the
persisted record, with no inference substituting a different value: there is
a single supported record shape, and whatever its `key_origin` field decodes
to is the answer.

| What was found | Resolves to | Why |
|---|---|---|
| no metadata record | `unknown` → attests | the record cannot say how the key arrived; unknown is not a claim of import |
| a record with no origin recorded | `unknown` → attests | the field was never stamped; same reasoning as no record at all |
| a record with an origin | that origin | the record says so |
| a value this build does not recognise | refused | a vocabulary from a later version, or a defect |

Only the pkcs8 provider persists an origin today, so a key held by a hardware
backend reports `unknown`. That attests rather than refusing — refusing would
make every hardware-backed slot unattestable, including keys generated in the
slot, which is the case attestation exists for. It is safe because
`ImportPIVKey` reads the provenance back after writing it and **rolls the
import back** if the backend did not record it, so a backend that records
nothing cannot be holding an imported key. A non-empty origin this build does
not recognise is still refused.

That safety is a property of there being exactly one import path. `ImportPIVKey`
is the only way an outside key reaches a slot and `PIVKeyImporter` the only
capability that places one, so every import passes through the readback. **A
second import path that skipped it would break the implication with no
symptom** — keys it placed would report no origin and be attested as though
generated. Anyone adding one must carry the readback with it, or the
attestation rule has to stop trusting an unrecorded origin, which costs every
hardware-backed slot its attestation.

Separately, a slot may carry a certificate whose key this process does not hold
at all — it lives in another backend, or the in-memory generator was restarted.
There is no provenance to judge there and no claim is being strengthened, so
attestation of the stored certificate proceeds as it always has. "Not held
here" and "held, with an unrecognised origin" are deliberately different
answers.

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
