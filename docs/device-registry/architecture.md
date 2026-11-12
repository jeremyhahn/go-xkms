# Device registry: architecture

Row: device-registry (`docs/SPEC.md:87`). This document is the row's detail doc.

## Two modes

| Mode | Who is the authority | Where the record lives |
|---|---|---|
| Local (embedded) | the xkey host the phone paired with | `pairing.PairedDevice` (`xkey/pkg/pairing/device.go:39`), one row of `devices.yaml`, owned as described in `xkey/docs/phone-hsm/architecture.md:83` |
| Backend | go-xkms, the verifier for a tenant | `devicereg.Device` (`pkg/devicereg/registry.go:50`), one qrdb record per tenant and device ID |

Local mode already exists. Backend mode is new with `pkg/devicereg`: it gives
go-xkms a record of which devices a tenant paired, so a later slice can verify
and revoke them. The root module does not import xkey (xkey depends on
go-xkms); the two records are separate types whose overlapping field names
(`Name`, `PairedAt`, `AttestationProtocolVersion`) match.

## The record

`Device` (`pkg/devicereg/registry.go:50`):

- `ID` - the record's key in the tenant, one path-safe name: 1 to 128 ASCII
  letters, digits, `.`, `_` or `-`, not `.` or `..` (`ValidateID`,
  `pkg/devicereg/registry.go:73`).
- `Name` - display name.
- `IdentityKey` - the device identity public key, SPKI DER. Required on pair.
- `AttestationProtocolVersion` - the attestation model the device paired
  under; the anti-downgrade term, as in the local record.
- `PairedAt`, `PairedBy` - when and by whom.
- `RevokedAt` - nil while active; set once by a revoke.

## The registry

`Registry` (`pkg/devicereg/registry.go:113`) is built by `NewRegistry` on a
`*qrdbsdk.DAOFactory` (`pkg/devicereg/registry.go:119`), in the pattern of the
appraisal store's collections (`pkg/attestation/appraisal/store.go:198`): one
qrdb entity type (`paired_devices` in database `devices`) whose ID is a hash
of the tenant-scoped natural key.

- `Pair` (`pkg/devicereg/registry.go:138`) refuses a nil device, a device with
  no identity key or already revoked, and an ID the tenant already holds,
  active or revoked (`ErrDeviceExists`). A revoked ID is never reused: a
  re-pair takes a new ID.
- `Get`, `IsActive` - `ErrDeviceNotFound` for an ID the tenant does not hold.
- `List` (`pkg/devicereg/registry.go:172`) - the tenant's devices, active and
  revoked, ordered by ID.
- `Revoke` (`pkg/devicereg/registry.go:204`) - idempotent: the first
  revocation time is kept, the record is never deleted.

Pair is atomic in the store: it creates the record with the DAO's `SaveIfAbsent` (the KV store's `PutIfAbsent`), so of two registries on one store (two go-xkms processes) pairing one ID exactly one wins, and a store without atomic writes is refused. Revoke is atomic in the store too: it writes with the DAO's `CompareAndSwap` against the record it read, so of two registries revoking one device exactly one writes and the first revocation time is kept; a lost swap re-reads and returns nil, a swap lost 8 times is a `StoreError` matching `ErrRevokeConflict`, and a store without atomic writes is refused.

## Tenant scoping

Every key is `scope.SharedPrefix(tenant, "paired-devices") + ID`
(`tenantPrefix`, `pkg/devicereg/registry.go:245`). An empty or malformed tenant
is refused with `ErrInvalidTenant` on every call. Because the tenant is part of
the key, tenant A's `Get` or `Revoke` of tenant B's ID finds nothing
(`ErrDeviceNotFound`), and `List` returns only the caller's tenant.

## Deferred to row device-share-policy

The permissions (`device:pair` and the rest), the HTTP routes and the service
verbs that expose the registry. That row is blocked on go-qrdb. This row adds
no permission, route or service verb.
