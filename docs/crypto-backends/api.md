# Crypto Backends — API

> **Status: NORMATIVE** · Feature: `crypto-backends` · Repo: `go-xkms` · Last verified: 2026-08-19

The six transports and how they are shaped are described once, in
[`../key-management/api.md`](../key-management/api.md) §"How the six transports
are shaped". This page covers only the backend-discovery capabilities; every
*operation* a backend performs is reached through the key-management surface.

## Capability matrix

| Capability | REST | gRPC / Unix (`KeystoreService.`) | QUIC (HTTP/3) | MCP | Embedded | Permission |
|---|---|---|---|---|---|---|
| List backends | `GET /api/v1/backends` | `ListBackends` | same as REST | `xkms.listBackends` | `BackendService.ListBackends` | `backends:list` |
| Get backend + capabilities | `GET /api/v1/backends/{id}` | `GetBackendInfo` | same as REST | `xkms.getBackend` | `BackendService.GetBackend` | `backends:read` |
| Algorithm vocabulary | `GET /api/v1/algorithms` | `Algorithms` | same as REST | `xkms.algorithms` | `BackendService.Algorithms` | public |
| Server capabilities (which subsystems are configured) | `GET /api/v1/capabilities` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | — | public |

`GET /api/v1/algorithms` and `GET /api/v1/capabilities` are `RouteAuthPublic`
and served under `GroupRoot`, so they answer before authentication. They are
what a client uses to negotiate.

## Response schema

`GetBackend` returns `transport.BackendInfo`, whose capability block is
`types.Capabilities` (`pkg/types/types.go:1366`) — the same struct the server
uses internally, so what a client sees is what the server will enforce:

```
Keys, HardwareBacked, Signing, Decryption, KeyRotation, SymmetricEncryption,
Sealing, Import, Export, KeyAgreement, ECIES, Attestation, QuantumSigning,
KeyEncapsulation, SecurityLevel
```

`ListBackends` takes `ListOption` values and pages
(`pkg/api/transport/pagination.go`).

## Status and error mapping

Standard mapping — see [`../key-management/api.md`](../key-management/api.md)
§"Status and error mapping". Backend-specific cases:

| Condition | REST | gRPC / Unix | MCP |
|---|---|---|---|
| backend name not configured | 404 | `NotFound` | error object |
| backend compiled out (no build tag) | 501 | `Unimplemented` | error object |
| device or provider unreachable | 503 | `Unavailable` | error object |
| PIN / password required first | 401 | `Unauthenticated` | error object |

## Not on the wire

Backend *construction* — `xkms.Backend`, `xkms.BackendConfig`, the
`pkg/server/backend_<backend>.go` set — is in-process only and deliberately has
no transport surface. Deciding which backends a deployment runs is configuration,
not an API call. Remote reconfiguration would make a server's crypto posture
changeable by anyone holding an admin token, which is the opposite of what the
hardware is for.

## Versioning and deprecation

`/api/v1` and gRPC package `xkmsv1`. Adding a field to `types.Capabilities` is
additive and safe; removing one is a breaking change to the wire contract and
requires a coordinated release.
