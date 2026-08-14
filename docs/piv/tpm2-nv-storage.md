# PIV Certificate Storage: TPM 2.0 NV Backend

`pkg/pivcert/tpm2` stores PIV certificates in TPM 2.0 NV (Non-Volatile) RAM. It
is one of the three `pivcert.PIVCertificateStorage` backends, alongside
`pkg/pivcert/file` and `pkg/pivcert/pkcs11`.

The backend is an adapter: all NV access is delegated to
`pkg/storage/hardware.TPM2CertStorage`, the canonical NV certificate store. The
adapter contributes the PIV-specific concerns: the slot to NV index binding,
slot metadata, and the mapping of TPM failures onto the pivcert sentinels.

## Slot to NV index mapping

`hardware.TPM2CertStorage` addresses NV RAM by certificate ID:

```
NV index = BaseIndex + (xxhash64(certificate ID) mod 0x00400000)
```

and writes the ID into a record header stored at that index. The adapter binds
each PIV slot to one immutable certificate ID (`slotmodel.go`):

| Slot | Certificate ID | Slot | Certificate ID |
|------|----------------|------|----------------|
| 9a (Authentication) | `piv-cert-9a` | 82-95 (Retired 1-20) | `piv-cert-82` ... `piv-cert-95` |
| 9c (Digital Signature) | `piv-cert-9c` | | |
| 9d (Key Management) | `piv-cert-9d` | | |
| 9e (Card Authentication) | `piv-cert-9e` | | |
| f9 (Attestation) | `piv-cert-f9` | | |

Because the index is a pure function of a compile-time constant, the mapping is:

- **Deterministic** -- a slot always resolves to the same NV index for a given
  base index.
- **Stable across restarts** -- nothing lives in process memory or in a
  host-side index file. A certificate stored today is found tomorrow by
  recomputing the hash; the record header lets the storage confirm the index
  really holds that slot's certificate.
- **In range** -- the modulus keeps every index inside
  `[BaseIndex, BaseIndex+0x00400000)`.
- **Collision-free** -- the IDs are fixed, so the 25 resulting indices are
  fixed. `TestPIVSlotCertIDs_MapToDistinctNVIndices` stores into every slot on
  the embedded simulator and asserts 25 distinct in-range NV indices. Should a
  slot ever collide with another record, the ID header makes the storage refuse
  the write rather than clobber the occupant, and `Store` reports
  `ErrStorageFull`.

The certificate IDs are part of the on-device format. Changing one orphans
every certificate already stored under the old value.

## Configuration

```go
store, err := tpm2.New(&tpm2.Config{
    TPM:         tpm,        // open transport.TPM, stays owned by the caller
    BaseIndex:   0x01800000, // zero selects DefaultBaseIndex
    MaxCertSize: 2048,       // zero selects DefaultMaxCertSize
    OwnerAuth:   ownerAuth,  // TPM owner hierarchy authorization
})
```

`Close` releases the PIV store without closing the TPM, so one TPM connection
can back a PIV store alongside the rest of the platform's TPM use.

`tpm2.NewFromCertStorage(hw)` wraps a `hardware.HardwareCertStorage` a caller
already built for the TPM, and `store.CertStorage()` returns it, so the slot
model and the certificate store share one view of NV RAM.

Note that `pivcert.DefaultTPM2BaseIndex` (`0x01C00100`) is above the NV range
the hardware certificate storage addresses and is rejected; use
`tpm2.DefaultBaseIndex`.

## Error mapping

TPM failures are translated into the sentinels `PIVCertificateStorage`
documents. The originating error stays reachable through `errors.Is`, so a
caller can still read the TPM response code.

| Condition | Sentinel |
|-----------|----------|
| Empty slot, `TPM_RC_HANDLE` | `ErrCertificateNotFound` |
| Unknown slot identifier | `ErrInvalidSlot` |
| `TPM_RC_NV_SPACE`, NV index held by another record | `ErrStorageFull` |
| Record beyond `MaxCertSize` or `MaxCertSizeTPM2` | `ErrCertificateTooLarge` |
| `TPM_RC_BAD_AUTH`, `TPM_RC_AUTH_FAIL`, `TPM_RC_NV_AUTHORIZATION` | `ErrPermissionDenied` |
| Command never reached the TPM (no response code) | `ErrTPMNotAvailable` |
| Store used after `Close` | `ErrStorageClosed` |

A TPM that cannot be reached is deliberately never reported as an empty slot: a
caller that believed the slot empty would re-issue over a live certificate.

## Slot model

`tpm2.NewPIVSlotModel(hw)` implements `pivcert.SlotModel` over the same NV
records. A slot counts as occupied when NV RAM holds a certificate for it; the
TPM keeps PIV keys outside this storage, so certificate presence is the only
occupancy signal available. `NextAvailable` hands out retired slots (82-95)
first and never auto-allocates 9a or 9e. Records written by other subsystems
into the same NV range are ignored.

## Capacity

TPM NV RAM is small. Each PIV certificate consumes an NV index sized to the
PEM-encoded certificate plus its ID header, so a typical device holds only a
handful of certificates. `Store` reports `ErrStorageFull` when the device
refuses another allocation; freeing a slot with `Delete` makes room again.

## SDK

The backend is re-exported behind the `tpm2` build tag in
`sdk/go/pivcert_backends_tpm2.go`, mirroring the PKCS#11 split:

```go
store, err := xkms.NewPIVTPM2Backend(&xkms.PIVTPM2Config{TPM: tpm})
model, err := xkms.NewPIVTPM2SlotModel(store.CertStorage())
```

`PIVStorageTypeTPM2`, `PIVMaxCertSizeTPM2` and the PIV sentinels are exported
unconditionally from `sdk/go/pivcert.go`.

## Tests

```
go test -tags "codec_json tpm_simulator" ./pkg/pivcert/tpm2/
go test -race -tags "codec_json tpm_simulator" ./pkg/pivcert/tpm2/
```

Hardware-backed tests run against the embedded TPM simulator behind the
`tpm_simulator` build tag and never touch a host TPM device. The
simulator is process-wide, so these tests do not run in parallel.
