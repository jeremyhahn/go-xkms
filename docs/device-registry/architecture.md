# Device registry: architecture

Row: device-registry (`docs/SPEC.md:87`). This document is the row's detail doc.

## Two modes

| Mode | Who is the authority | Where the record lives |
|---|---|---|
| Local (embedded) | the xkey host the phone paired with | `pairing.PairedDevice` (`xkey/pkg/pairing/device.go:39`), one row of `devices.yaml`, owned as described in `xkey/docs/phone-hsm/architecture.md:83` |
| Backend | go-xkms, the verifier for a tenant | `devicereg.Device` (`pkg/devicereg/registry.go:44`), one qrdb record per tenant and device ID |

Local mode: `PhoneService.Connect`
(`xkey/pkg/gui/services/phone_service.go:1160`) refuses a device name with no
pairing record and pins the Noise session to the record's key (`:1206`,
`:1242`); a session with no pinned key is refused with `ErrUntrustedDevice`
(`xkey/pkg/phone/phone.go:375`). Backend mode is `pkg/devicereg`: go-xkms's
record of which devices a tenant paired, checked with `IsActive`
(`pkg/devicereg/registry.go:229`) and revoked with `Revoke`. The root module does not import xkey (xkey depends on
go-xkms); the two records are separate types whose overlapping field names
(`Name`, `PairedAt`, `AttestationProtocolVersion`) match.

## The record

`Device` (`pkg/devicereg/registry.go:44`):

- `ID` - the record's key in the tenant, one path-safe name: 1 to 128 ASCII
  letters, digits, `.`, `_` or `-`, not `.` or `..` (`ValidateID`,
  `pkg/devicereg/registry.go:67`).
- `Name` - display name.
- `IdentityKey` - the device identity public key, SPKI DER. Required on pair.
- `AttestationProtocolVersion` - the attestation model the device paired
  under; the anti-downgrade term, as in the local record.
- `PairedAt`, `PairedBy` - when and by whom.
- `RevokedAt` - nil while active; set once by a revoke.

## The registry

`Registry` (`pkg/devicereg/registry.go:115`) is built by `NewRegistry` on a
`*qrdbsdk.DAOFactory` (`pkg/devicereg/registry.go:120`), in the pattern of the
appraisal store's collections (`pkg/attestation/appraisal/store.go:198`): one
qrdb entity type (`paired_devices` in database `devices`) whose ID is a hash
of the tenant-scoped natural key.

- `Pair` (`pkg/devicereg/registry.go:137`) refuses a nil device, a device with
  no identity key or already revoked, and an ID the tenant already holds,
  active or revoked (`ErrDeviceExists`). A revoked ID is never reused: a
  re-pair takes a new ID.
- `Get`, `IsActive` - `ErrDeviceNotFound` for an ID the tenant does not hold.
- `List` (`pkg/devicereg/registry.go:175`) - the tenant's devices, active and
  revoked, ordered by ID. Each record carries its tenant prefix in an indexed
  `Tenant` field, and List queries that index, so it reads only the tenant's
  own records, never the whole collection.
- `Revoke` (`pkg/devicereg/registry.go:198`) - idempotent: the first
  revocation time is kept, the record is never deleted.

Pair is atomic in the store: it creates the record with the DAO's `SaveIfAbsent` (the KV store's `PutIfAbsent`), so of two registries on one store (two go-xkms processes) pairing one ID exactly one wins, and a store without atomic writes is refused. Revoke is atomic in the store too: it writes with the DAO's `CompareAndSwap` against the record it read, so of two registries revoking one device exactly one writes and the first revocation time is kept; a lost swap re-reads and returns nil, a swap lost 8 times is a `StoreError` matching `ErrRevokeConflict`, and a store without atomic writes is refused.

## Tenant scoping

Every key is `scope.SharedPrefix(tenant, "paired-devices") + ID`
(`tenantPrefix`, `pkg/devicereg/registry.go:250`). An empty or malformed tenant
is refused with `ErrInvalidTenant` on every call. Because the tenant is part of
the key, tenant A's `Get` or `Revoke` of tenant B's ID finds nothing
(`ErrDeviceNotFound`), and `List` returns only the caller's tenant.

## Deferred to row device-share-policy

The permissions (`device:pair` and the rest), the HTTP routes and the service
verbs that expose the registry. That row is blocked on go-qrdb. This row adds
no permission, route or service verb.
