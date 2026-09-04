# PIV Smartcard — Engineering Contract

> **Status: NORMATIVE** · Feature: `piv-smartcard` · Repo: `go-xkms` · Last verified: 2026-09-03

## Exported surface — `pkg/pivcert`

### Types

```go
type PIVStorageType string   // "file" | "tpm2" | "pkcs11"
const (
	StorageTypeFile   PIVStorageType = "file"
	StorageTypeTPM2   PIVStorageType = "tpm2"
	StorageTypePKCS11 PIVStorageType = "pkcs11"
)
func (t PIVStorageType) String() string
func (t PIVStorageType) IsValid() bool

type PIVSlot string          // "9a" … "f9", "82" … "95"
func ValidateSlot(slot PIVSlot) error
func AllSlots() []PIVSlot
func PrimarySlots() []PIVSlot
func RetiredSlots() []PIVSlot
func GetNVIndex(slot PIVSlot, baseIndex uint32) (uint32, error)

type CertFormat int          // PEM / DER
type PIVSlotInfo struct{ … }
type SlotMetadata struct{ … }
type SlotOccupancyInfo struct{ … }
```

Slot constants: `PIVSlotAuthentication` (`9a`), `PIVSlotDigitalSignature`
(`9c`), `PIVSlotKeyManagement` (`9d`), `PIVSlotCardAuthentication` (`9e`),
`PIVSlotAttestation` (`f9`), and `PIVSlotRetired1`…`PIVSlotRetired20` (`82`–`95`).

### Interfaces

```go
type PIVCertificateStorage interface { /* put / get / delete a certificate in a slot */ }
type PIVSlotRegistry interface       { /* enumerate and describe slots */ }

type SlotModel interface {
	// … prefers retired slots (82-95) over primary slots (9a-9e)
	// to preserve standard PIV slot semantics
	SlotOccupancy(slot PIVSlot) (*SlotOccupancyInfo, error)
}
```

### Configuration types

`PIVConfig`, and one per storage type: `FileStorageConfig`,
`TPM2StorageConfig`, `PKCS11StorageConfig`.

### Verification

```go
func VerifyChain(leaf *x509.Certificate, roots, intermediates *x509.CertPool) error
func ThumbprintSHA256(cert *x509.Certificate) string

type VerifyError struct{ … }
type VerifyChainError struct{ … }
```

### Errors

```go
type PIVStorageError struct{ … }
func NewStorageError(op string, slot PIVSlot, err error) *PIVStorageError
func NewStorageTypeError(op string, storageType PIVStorageType, err error) *PIVStorageError
```

`PIVStorageError` carries the operation and the slot, which is what makes a
storage failure diagnosable — "put failed" without the slot is useless.

### Keystore-side operations

`pkg/xkms/piv_manager.go`, `piv_ops.go`, `piv_keygen_backend.go` (hardware),
`piv_keygen_software.go` (software fallback). The generator seam is
`xkms.PIVKeyGenerator`, which is also what
[`../auth-factors/`](../auth-factors/engineering.md) injects.

## Invariants

- **A slot is always one of the defined constants.** `ValidateSlot` rejects
  anything else at the boundary; never accept a free-form slot string deeper in.
- **Allocation prefers retired slots.** `SlotModel` documents it: retired slots
  (82–95) are chosen over primary slots (9a–9e) so standard PIV semantics
  survive. Code that allocates `9a` for a general-purpose key is a defect.
- **`IsValid()` closes the storage-type set.** Three types, no others.
- **Export returns certificates, never private keys.**
- **The `f9` attestation certificate is evidence, not proof.** Run
  `VerifyChain` before believing it.
- **An attestation over an imported key asserts residency, not exclusivity.**
  `ImportPIVKey` admits a second class of key into a slot: one that may exist
  elsewhere. A slot-generated key cannot have existed before it existed in the
  slot; an imported one can, and no property of the slot afterwards separates
  the two. `VerifyChain` does not recover the difference — it anchors the
  attestation to a manufacturer, which establishes that the card is genuine,
  not that the key was born on it. Code that treats "attested" as "unique" is
  a defect. See [`architecture.md`](architecture.md).
- **An imported key is not attestable.** `AttestPIVSlot` refuses a slot whose
  key origin is `types.KeyOriginImported`, with
  `ErrPIVKeyImportedNotAttestable`, before producing any material. The slot
  usually *has* a certificate, so attestation is mechanically possible — that
  is exactly why the refusal must be explicit. A test that only checks the
  happy path passes against a build that attests imported keys happily.
- **Provenance is recorded by the system, never accepted from a caller.**
  `types.KeyOrigin` is stamped by the code path that ran; `stampKeyOrigin`
  strips and recomputes whatever a caller supplied, exactly as PKCS#11 strips
  token-computed attributes from a template. A provenance field a caller can
  set is worse than no field, because a verifier reads it as authoritative.
- **Attestation fails closed on the origin.** `refuseUnattestableKey` refuses
  anything that is not `types.KeyOriginGenerated`, not merely `imported`. A
  check that refuses only the known-bad values starts attesting silently the
  day a write path forgets to record an origin.
- **The legacy inference lives at the metadata boundary, once.**
  `pkcs8.resolveKeyOrigin` resolves a record with no origin field — schema < 2,
  or no record at all — to `generated`, because such a key predates every PIV
  import path. A schema-2 record with **no** origin is a defect rather than a
  legacy key and stays unknown, so it is refused. Do not move this inference
  into the attestation check; that is what makes it a fallback instead of a
  bounded resolution.
- **"Not held here" is not "unknown origin".** `PIVKeyOrigin` returns a found
  flag. A generator holding no key for the slot reports not-found, and
  attestation of the stored certificate proceeds — refusing there would make
  every software-PIV slot unattestable after a restart, and there is no
  provenance to judge.
- **Provenance must survive persistence, and the import verifies that it did.**
  `keyMetadata` schema 2 carries it (`pkg/keyprovider/pkcs8`), and the import
  path writes that record too — it previously wrote none, so tenant,
  exportability, digest and origin were all lost for imported keys (#162).
  `ImportPIVKey` then **reads the origin back** and rolls the import back with
  `ErrPIVImportProvenanceNotRecorded` if the backend did not record it. A
  backend that does not persist the origin therefore cannot hold an imported
  key at all — the guarantee is structural rather than a warning in this file.

  **What that guarantee stands on, for whoever adds the next import path.**
  "No recorded origin implies not imported" holds because `ImportPIVKey` is the
  only way a key is placed into a slot from outside, and `PIVKeyImporter` the
  only capability that does it — so every import passes through the readback
  above. An import path added elsewhere that writes key material without
  reading the provenance back would break that implication **silently**: keys
  it placed would report no origin, and attestation would treat them as
  generated. If you add one, it must perform the same readback, or the
  attestation rule has to stop trusting an unrecorded origin — and that second
  option costs every hardware-backed slot its attestation, which is why the
  readback is the cheaper half of the bargain.
- **An unrecorded origin attests; an unrecognised one does not.** Only the
  pkcs8 provider persists an origin today, so every hardware backend reports
  none. Refusing on that would make every hardware-backed slot unattestable,
  including keys generated in the slot — the case attestation exists for. It is
  safe because the import gate above means an unrecorded origin provably is not
  an import. A non-empty origin this build does not recognise is still refused.
- **Import refusal is reported, never silent.** A backend that cannot accept an
  imported key yields `ErrPIVImportNotSupported`. A real applet may refuse
  particular slots or algorithms, and a caller has to be able to tell that from
  success.
- **A declared algorithm is checked, never authoritative.** `ImportPIVKeyRequest.Algorithm`
  is validated against the supplied key (`ErrPIVAlgorithmMismatch`); the key
  itself decides. A caller that believes it is importing one algorithm must not
  silently end up with another.
- **TPM2 NV indices are derived, not assigned.** `GetNVIndex(slot, baseIndex)`
  is deterministic from the configured base; two deployments sharing a TPM must
  not share a base.
- **Storage and slot semantics are independent.** The same slot model applies
  whether the bytes land in a file, NV, or a token.
- **Concurrency.** Storage implementations serialise device access; the slot
  model itself is stateless.

## Error semantics

`PIVStorageError` (op + slot + cause) and `PIVStorageTypeError` for the
type-level failures. Chain verification failures are `VerifyError` /
`VerifyChainError`. Typed throughout; no `fmt.Errorf`.

**Fail closed:** an invalid slot, an unreadable device, a full NV space, a
certificate whose chain does not verify, or a format mismatch all return an
error. Nothing writes to a different slot than the one requested, and nothing
falls back to file storage when the configured hardware is unavailable.

## Configuration

`PIVConfig` selects the storage type and carries the matching sub-config:

- **`FileStorageConfig`** — the directory holding certificates.
- **`TPM2StorageConfig`** — the NV base index. `GetNVIndex` derives per-slot
  indices from it. Choose a base that does not collide with other NV users on
  the same TPM.
- **`PKCS11StorageConfig`** — module path, slot, PIN handling.

`xkmsctl` supplies the client side through the global `--pkcs11-module`,
`--pkcs11-slot`, `--pkcs11-pin` and `--backend` flags.

## Persistence

Per storage type: files on disk, TPM2 NV indices, or PKCS#11 token objects.
`SlotOccupancyInfo` reports what is actually in a slot, which is the only
reliable way to know — the three stores have no shared index.

Compatibility: slot identifiers and PIV certificate encodings are NIST-defined
and stable. The TPM2 NV index derivation is ours; changing `GetNVIndex` would
orphan every existing NV-stored certificate and is a migration, not a change.

## Test strategy

- **Unit** — `pkg/pivcert/pivcert_test.go`, `slotinfo_test.go`,
  `verify_test.go`; per-storage suites under `pkg/pivcert/{file,tpm2,pkcs11}`.
- **Keystore side** — `pkg/xkms/piv_manager_test.go`, `piv_ops_test.go`,
  `piv_keygen_backend_test.go`, `piv_keygen_software_test.go`.
- **Transport** — `pkg/api/rest/handlers_piv_test.go`,
  `pkg/api/mcp/handlers_piv_test.go`.
- **SDK** — `sdk/go/piv_test.go`, `piv_signer_test.go`,
  `pivcert_backends*.go`.
- **Integration** — `test/integration/pkcs11`, `test/integration/tpm2`.
- **Fault injection** — NV exhaustion and slot-collision cases live in the tpm2
  storage suite.

## Observability

Storage operations log the slot and storage type with the correlation ID;
`PIVStorageError` carries both, so a log line identifies the exact slot that
failed. Certificate thumbprints (`ThumbprintSHA256`) are the stable identifier
to log — never the certificate body.
