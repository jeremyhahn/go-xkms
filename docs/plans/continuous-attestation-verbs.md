# Continuous attestation: verdict verbs (epic #2088, slice 2)

## Objective

Serve the verdicts that `pkg/attestation/continuous` (slice 1) stores as xkms
service verbs on REST, tenant-bound like the signing-key verbs, so a client
can read a device's verdicts and ask for a fresh one.

Check before the first edit: no `AttestationVerdict` symbol existed in
pkg/xkms, pkg/api/rest or pkg/api/transport on the row tip d238dc046.

## Verbs

| Verb | Permission | Route |
| --- | --- | --- |
| `ListAttestationVerdicts(ctx, {DeviceID})` | `attestation_verdicts:list` | `GET /attestation/verdicts?device=` |
| `GetLatestAttestationVerdict(ctx, {DeviceID})` | `attestation_verdicts:get` | `GET /attestation/verdicts/latest?device=` |
| `ReattestDevice(ctx, {DeviceID})` | `attestation_verdicts:create` | `POST /attestation/verdicts` body `{"device_id": ...}` |

- Wiring: `XKMSService.SetContinuousAttestation(engine, store)`.
- Tenant: always `callerTenant(ctx)`; no request type carries a tenant.
- Not configured: no store wired gives `ErrNotConfigured` (503); a store but
  no engine gives `ErrNotConfigured` on `ReattestDevice` only.
- Errors: empty device ID is an `InputError` (400); no verdict is
  `VerdictNotFoundError` (404).
- Permissions: resource `attestation_verdicts` in pkg/auth, ScopeSelf for
  list/get/create in pkg/apimodule.

## Tests

- Servicer: not configured, empty device ID, tenant isolation, latest after
  two re-attests, re-attest through a fake EvidenceSource and Appraiser.
- REST: 200, 400, 404, 503 and each route's permission.

## Out of scope

Compose wiring with a real EvidenceSource, gRPC, MCP, sdk/go re-export
(later slices).

## Results

Results to follow.
