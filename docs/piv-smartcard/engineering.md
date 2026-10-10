# PIV Smartcard — Engineering Contract

> **Status: NORMATIVE** · Feature: `piv-smartcard` · Repo: `go-xkms` · Last verified: 2026-10-09

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

Two optional capabilities a `PIVKeyGenerator` may additionally implement,
both satisfied by `backendPIVKeyGenerator` and `softwarePIVKeyGenerator`
(`pkg/xkms`):

```go
type PIVKeyOriginReporter interface {
	PIVKeyOrigin(slot pivcert.PIVSlot, cn string) (origin types.KeyOrigin, found bool, err error)
}

type PIVAttestLevelReporter interface {
	AttestLevel(slot pivcert.PIVSlot, cn string) (types.AttestLevel, error)
}
```

`types.AttestLevel` (`pkg/types`, alongside `types.KeyOrigin`):
`AttestLevelHardware`, `AttestLevelSoftware`, `AttestLevelUnattested`
(`String()`, `ParseAttestLevel(s string) (AttestLevel, error)` returning
`types.ErrUnknownAttestLevel` on an unrecognized value, JSON/YAML tags
`attest_level`). `types.KeyAttributes.AttestLevel` sits next to `KeyOrigin`
on the same struct — see [`architecture.md`](architecture.md) for why they
are siblings, not one field, and #220 for the ownership ruling that put xkms
in charge of this vocabulary for go-quicbaas#379 as well.

`rest.PIVLoginOptions.RecordedLevel` (`pkg/api/rest`) is the resolver the PIV
login exchange consults before falling back to the certificate-chain
decision:

```go
RecordedLevel func(cert *x509.Certificate) (level types.AttestLevel, found bool)
```

`pkg/server` wires it, at REST composition, to
`PIVManager.AttestLevelForCertificate`:

```go
func GetPIVManager() (*PIVManager, error)

func (m *PIVManager) AttestLevelForCertificate(ctx context.Context, cert *x509.Certificate) (types.AttestLevel, bool, error)
```

`AttestLevelForCertificate` computes `cert`'s SPKI SHA-256 thumbprint with
`qrdbsdk.ComputeSPKIThumbprint` (`go-qrdb/sdk/go`) — the one cert-binding
algorithm the stack uses everywhere an mTLS identity is resolved, never a
second one invented for this lookup — and scans the enrolled slots of every
backend with a registered PIV store (`RegisterPIVStore`, or one resolved
once through the configured backend resolver; a name this manager has never
seen is not probed) for a certificate sharing that thumbprint. A match
resolves the level through that backend's `PIVAttestLevelReporter` via
`pivAttestLevel`. `found=false` with a nil error means no enrolled slot's
key matches — the ordinary case for a certificate unrelated to any PIV
enrollment, not a failure. `ErrPIVAttestLevelLookupFailed` is returned only
when a registered backend's store cannot be listed or its generator cannot
be resolved — a system failure the login path needs to know about rather
than silently reading as no match. `GetPIVManager` returns
`ErrPIVNotInitialized` when no manager exists yet; `pkg/server` treats that
as "RecordedLevel stays nil," not a composition failure, since a build with
no PIV backends configured has no PIV manager to wire.

## Slot attestation: reading the evidence back

`pkg/pivcert` parses the vendor extensions a PIV slot-attestation certificate
carries, so a consumer can enforce a policy rather than only observe that a
chain anchored.

```go
func ParseAttestation(cert *x509.Certificate) (*Attestation, error)
func VerifyAttestation(chain []*x509.Certificate, opts *AttestationVerifyOptions) (*Attestation, error)
func BuildAttestationExtensions(att *Attestation) ([]pkix.Extension, error)
```

Extensions read, from Yubico's `1.3.6.1.4.1.41482.3` arc: firmware version
(`.3`), serial number (`.7`), PIN and touch policy (`.8`), form factor (`.9`,
high bit marks FIPS). Re-exported through `sdk/go` with a `PIV` prefix.

### Scope of validation — read this before trusting a decoded value

**The layout is Yubico's documented one and has NOT been validated against a
physical device.** No YubiKey was available, so there is no captured
certificate to test against, and every fixture in the package's tests is built
by the package's own encoder. That is a closed loop: it proves the parser and
the builder agree, never that either matches real hardware.

The design answers that rather than hiding it:

- Every field is decoded **strictly** — exact lengths, exact ASN.1 types.
  Nothing is coerced.
- A value that does not match is reported **unparseable**, and the field stays
  nil. A device whose framing differs surfaces as "I could not read this",
  which a caller can act on, instead of a confidently wrong touch policy,
  which it cannot.
- `TestParseAttestation_WrongFramingIsUnparseableNotAWrongValue` builds the
  most likely alternative framing — each value wrapped in an inner
  `OCTET STRING` rather than raw in `extnValue` — and asserts it yields
  unparseable rather than a plausible value. **That test is what makes the
  limitation safe rather than merely disclosed**; do not relax the length
  checks it guards.

If a real attestation certificate becomes available, add it as a fixture the
way `pkg/attestation/android/testdata/android_emulator_chain.txt` is used, and
this section can be narrowed to what the fixture does not cover.

### Absent, unparseable, and unrecognised are three different answers

| Situation | Field | `Unparseable` | Meaning |
|---|---|---|---|
| extension not present | nil | no | the device does not report it |
| present, did not decode | nil | **yes** | the evidence is not being understood |
| decoded, value unknown to this build | set, `Known()` false | no | newer firmware, or a value we do not model |

Collapsing the first two would let "this device does not report touch policy"
and "this device reports something I cannot read" produce the same verdict,
and they warrant opposite responses. The third is not a failure at all: the
extension decoded, and a caller comparing against a known constant simply will
not match.

### Trust anchors are the caller's

`AttestationVerifyOptions.TrustedRoots` is supplied by the caller and **this
package ships no vendor root**. Which root a deployment trusts is its decision,
not a library's — the same shape `pkg/attestation/android` uses, where the
embedded Google root is offered separately as an opt-in rather than baked into
verification. A nil or empty pool is an error, not a pass: an unanchored
attestation is evidence of nothing.

`ParseAttestation` deliberately performs no trust evaluation, so a deployment
with no vendor root configured keeps the presence check it already has
(`Attestation.HasAttestationExtensions`) instead of choosing between a full
verdict and none.

The PIV login exchange (`POST /api/v1/auth/login/piv`) is the in-repo consumer:
it runs `VerifyAttestation` over each certificate the client presents with the
anchors from `auth.piv_login.attestation_roots`, and treats a verified chain as
proof only when its subject key equals the login certificate's, so a chain
that verifies for some other key proves nothing about this login.

### A verified chain is not a satisfied policy

`VerifyAttestation` returning a nil error means the **chain** verified. The
certificate may carry no readable claim at all — a software-backed slot's
certificate is one xkms self-signed, and it carries none. Callers enforcing a
policy must check the field they care about; `HasAttestationExtensions` reports
whether there is any evidence to check.

## Invariants

- **A slot is always one of the defined constants.** `ValidateSlot` rejects
  anything else at the boundary; never accept a free-form slot string deeper in.
- **Allocation prefers retired slots.** `SlotModel` documents it: retired slots
  (82–95) are chosen over primary slots (9a–9e) so standard PIV semantics
  survive. Code that allocates `9a` for a general-purpose key is a defect.
- **`IsValid()` closes the storage-type set.** Three types, no others.
- **Export returns certificates, never private keys.**
- **The network slot operations are platform-scoped and reach the card only
  through the service** (go-xkms#1227). Each `XKMSService` PIV method calls
  `requirePlatformScope` before delegating to the package-level operation
  (`pkg/xkms/servicer_piv.go:31,40,49,58,67,76,85,94`); REST
  (`pkg/api/rest/handlers_piv.go`), gRPC/Unix (`pkg/api/grpc/service_piv.go`)
  and MCP (`pkg/api/mcp/handlers_piv.go`) call the service methods, never
  `xkms.ListPIVSlots` and its siblings directly. A new network PIV verb adds
  a service method with the check and an entry to `platformScopedOps`
  (`pkg/xkms/platform_scope_test.go`).
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
- **`resolveKeyOrigin` is a plain read, with no inference.** There is a
  single supported `keyMetadata` schema; whatever the record's `key_origin`
  field decodes to (including the zero value, when there is no record or the
  field was never stamped) is what `pkg/keyprovider/pkcs8.resolveKeyOrigin`
  returns. `refuseUnattestableKey` is the only place that decides what to do
  with `types.KeyOriginUnknown` — it attests, per the bullet below — so a
  future record shape must not reintroduce version-gated inference here to
  influence that decision.
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
- **`AttestLevel` is a property of the generator, not of any one key —
  unlike `KeyOrigin`, it needs no "found" return.** `PIVKeyOriginReporter`
  answers a fact that can only be known by consulting the specific key's own
  record (generated or imported), so it may find no record at all.
  `PIVAttestLevelReporter.AttestLevel` answers whether the *generator* is
  hardware-backed, which does not vary key to key, so it is always
  answerable by a generator that implements the interface. A generator that
  cannot back any hardware-backing claim simply does not implement
  `PIVAttestLevelReporter` — see `pivAttestLevel` (`pkg/xkms/piv_manager.go`)
  for the fallback that follows from its absence.
- **An absent `PIVAttestLevelReporter`, or one that errors, resolves to
  `AttestLevelUnattested` — never guessed at.** `pivAttestLevel` is the one
  place this fallback is applied, mirroring the fail-closed rule
  `refuseUnattestableKey` applies to an unrecognised `KeyOrigin`: a claim
  this build cannot back is recorded as no claim, not as the caller's
  preferred value.
- **`AttestLevel` and `KeyOrigin` are recorded together, at the same
  enrollment-time write, but answer independent questions.** Both
  `GeneratePIVKey` and `ImportPIVKey` stamp `attrs.AttestLevel` immediately
  after `attrs.KeyOrigin` in `backendPIVKeyGenerator`. An imported key on a
  hardware backend still records `AttestLevelHardware` — `AttestLevel` is not
  exempted from being set on the import path, because it answers *where the
  key lives*, which import does not change, not *whether the key is
  exclusive*, which `KeyOrigin` already covers and which is why `AttestPIVSlot`
  separately refuses an imported key regardless of its `AttestLevel`.
- **`pkg/keyprovider/pkcs8` never round-trips `AttestLevel` through its
  metadata record, by design — see [`architecture.md`](architecture.md).**
  Do not add an `AttestLevel` field to `keyMetadata` mirroring `KeyOrigin`'s:
  the structural invariant ("PKCS#8 storage is always software") makes a
  persisted, possibly-stale value strictly worse than the live, unconditional
  answer `ListKeys` already gives.
- **A recorded PIV login level takes precedence over the certificate chain,
  never a blend of the two.** `PIVLoginOptions.attestationLevel`
  (`pkg/api/rest`) consults `RecordedLevel` first; when it reports found, the
  chain is not examined at all for that decision. `AllowUnattested` still
  gates whether a non-hardware level — recorded or chain-derived — may log
  in; `RecordedLevel` only decides which level that is.
- **`AttestLevelForCertificate` matches on SPKI, not on certificate
  identity.** Two certificates issued for the same key — a renewal, or a
  distinct self-signed leaf minted over the same key at enrollment versus
  login time — produce the same `qrdbsdk.ComputeSPKIThumbprint` and
  therefore the same match. Comparing whole certificates (or the PKIX
  `Fingerprint` `PIVSlotInfo.List` reports, which hashes the DER, not the
  SPKI) would silently stop matching the day a slot's certificate is
  reissued for the same key.
- **`AttestLevelForCertificate` only scans backends this manager already
  knows about.** It iterates `PIVManager.stores`'s current keys, never a
  backend name it has not seen — invoking the lazy `StoreFactory` path
  `pivStore` uses for on-demand backends would create stores for names this
  lookup has no reason to touch, for every login.

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

- **`FileStorageConfig`** — `DAOs`, the go-qrdb DAO factory the composition
  root injects. A nil factory is refused with `ErrMissingDAOFactory`; the
  store never closes the factory.
- **`TPM2StorageConfig`** — the NV base index. `GetNVIndex` derives per-slot
  indices from it. Choose a base that does not collide with other NV users on
  the same TPM.
- **`PKCS11StorageConfig`** — module path, slot, PIN handling. `PIN` and
  `SOPIN` are `*secure.Secret`; a nil value means no PIN was configured, and
  each is opened only around the PKCS#11 login call that needs the
  plaintext.

`xkmsctl` supplies the client side through the global `--pkcs11-module`,
`--pkcs11-slot`, `--pkcs11-pin` and `--backend` flags.

## Persistence

Per storage type: go-qrdb DAO records, TPM2 NV indices, or PKCS#11 token
objects. `SlotOccupancyInfo` reports what is actually in a slot, which is the
only reliable way to know — the three stores have no shared index.

The software store (`pkg/pivcert/file`) keeps one `piv_certificates` record
per slot in the `pivcert` database, with the ID derived from the slot
identifier and lookups by it. The record holds the DER encoding and the time
it was stored; PEM is produced on export, and `List` derives each
`PIVSlotInfo` from the certificate (`NewSlotInfo`), sorted by slot. `Delete`
removes the record only if it is unchanged since it was read, and returns
`ErrConflict` when a concurrent `Store` replaced it. A record whose DER does
not parse reads as `ErrInvalidCertificate`. Hosts without a go-qrdb node
(xkey) build the factory over a `storage.Backend` with
`sdk/go.NewBackendDAOFactory`, one factory per backend namespace.

Compatibility: slot identifiers and PIV certificate encodings are NIST-defined
and stable. The TPM2 NV index derivation is ours; changing `GetNVIndex` would
orphan every existing NV-stored certificate and is a migration, not a change.

## Test strategy

- **Unit** — `pkg/pivcert/pivcert_test.go`, `slotinfo_test.go`,
  `verify_test.go`; per-storage suites under `pkg/pivcert/{file,tpm2,pkcs11}`.
  The file suite runs over a real in-memory go-qrdb DAO factory: round trip,
  persistence across stores on one factory, not-found, conflict on delete,
  corrupt records, and KV failures surfacing through `PIVStorageError`.
- **Keystore side** — `pkg/xkms/piv_manager_test.go`, `piv_ops_test.go`,
  `piv_keygen_backend_test.go`, `piv_keygen_software_test.go`,
  `piv_attest_level_test.go` (`PIVAttestLevelReporter` on both generators,
  `pivAttestLevel`'s capability/error fallback, enrollment-time stamping on
  both `GeneratePIVKey` and `ImportPIVKey`),
  `piv_attest_level_for_certificate_test.go`
  (`PIVManager.AttestLevelForCertificate`: a match on a hardware-enrolled
  key, a match on a software-enrolled key, no match, a nil certificate, and
  a backend listing failure surfacing `ErrPIVAttestLevelLookupFailed`).
- **`types.AttestLevel`** — `pkg/types/attest_level_test.go` (round trip,
  `ParseAttestLevel` error case, JSON/YAML); `pkg/keyprovider/pkcs8/attest_level_test.go`
  (`ListKeys` always resolves to software regardless of what was claimed).
- **Transport** — `pkg/api/rest/handlers_piv_test.go`,
  `pkg/api/mcp/handlers_piv_test.go`,
  `pkg/api/rest/handlers_auth_recorded_level_test.go` (`attestationLevel`'s
  precedence table, and the REST constants pinned to `types.AttestLevel`'s
  spelling).
- **Composition** — `pkg/server` (existing suite; exercises
  `restConfig.PIVLogin` construction, including the `RecordedLevel` wiring
  guarded on `xkms.GetPIVManager`).
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
