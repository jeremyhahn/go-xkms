# Plan: pkg/devicereg, the tenant-scoped paired-device registry (backend mode)

Row: device-registry (docs/SPEC.md:87). Epic #2093. Slice 1 of the row.

## Objective

In backend mode go-xkms is the verifier and authority for paired devices, but it
keeps no record of which devices a tenant paired. This slice adds a root-module
library, `pkg/devicereg`, that stores that record per tenant on the qrdb DAO
(the pattern of `pkg/attestation/appraisal/store.go`), and the row's detail doc.

## Record

`Device`:

- `ID` - one path-safe name (validated; the record's key).
- `Name` - display name.
- `IdentityKey []byte` - the device identity public key, SPKI DER.
- `AttestationProtocolVersion` - the attestation protocol version the device paired with.
- `PairedAt time.Time`, `RevokedAt *time.Time`, `PairedBy string`.

## API

- `NewRegistry(*qrdbsdk.DAOFactory) (*Registry, error)`.
- `Pair(ctx, tenant, *Device)` - refuses a duplicate ID (`ErrDeviceExists`).
- `Get(ctx, tenant, id)` - `ErrDeviceNotFound` when absent.
- `List(ctx, tenant)` - ordered by ID.
- `Revoke(ctx, tenant, id, at)` - idempotent, keeps the record.
- `IsActive(ctx, tenant, id)`.
- Every call refuses an empty tenant (`ErrInvalidTenant`); IDs are validated (`ErrInvalidID`).

## Checks

Test commit first: pair, duplicate, get, list order, revoke (idempotent),
revoked device inactive, tenant A cannot read or revoke tenant B's device,
invalid IDs and tenants, nil device, empty identity key.

## Out of scope

Permissions (`device:pair` and the rest), routes and service verbs: row
device-share-policy (blocked on go-qrdb). No dependency change. No import of xkey.

## Results to follow

(one line per run)
