# Host Embedding — API

> **Status: NORMATIVE** · Feature: `host-embedding` · Repo: `go-xkms` · Last verified: 2026-09-29

Host embedding adds no wire endpoints. It makes the existing xkms surfaces
answer on a host that mounts the `xkms` ServiceModule:

| Surface | REST | gRPC (`xkms.v1.KeystoreService`) | Enabled by |
|---|---|---|---|
| Password Manager | `/api/v1/passwords/*` | `Password*` | `WithQRDBClient` (+ `WithBarrierRegistry`, `WithPINBackend` for tenant stores) |
| SSH | `/xkms/v1/ssh/*` | `SSH*` | `WithQRDBClient` |
| Certificate Authority | `/api/v1/ca/*` | `GetCACertificate`, `SignCSR`, … | `WithCA` + `WithQRDBClient` |
| Platform sealed secrets | `/api/v1/platform/*` | `SealStore*` | `WithPlatformSealer` + `WithQRDBClient` |
| PCR policies | `/api/v1/policies/*` | `Policy*` | `WithPCRReader` + `WithQRDBClient` |
| Backend credentials | `/api/v1/credentials/*` | — | always (`manual`), `WithCredentialStrategy` |
| PIN management | `/api/v1/pin/*` | `*PIN*` | `WithPINBackend` |
| Barrier / custody / init | `/api/v1/barrier/*`, `/api/v1/custodian/*`, `/api/v1/shares/*`, `/api/v1/init/*` | `Barrier*`, custodian/share RPCs | `WithBarrierRoutes` + `WithBarrierRegistry` + `WithQRDBClient` |

Authorization is unchanged: each route and RPC carries its `resource:action`
permission and is enforced by the host's qrdb authorizer. Platform-scoped
surfaces (platform store, policies, barrier) refuse tenant-scoped callers.

Status codes on a self-built module:

- **503** until the host's XKMSService is composed, and for a feature whose
  subsystem is reached only through the service and is off ("not configured").
- **501** for a route whose handler family is not mounted (e.g. the CA without
  `WithCA`, passwords without storage).
- **404** for a barrier-family path without `WithBarrierRoutes`: the module did
  not register it, so the host may.

## Go SDK

```go
import (
    qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
    xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

module, err := xkmssdk.NewServiceModule(resolveXKMSService,
    xkmssdk.WithServiceModuleQRDBClient(func() *qrdbsdk.Client { return node.Client() }),
    xkmssdk.WithServiceModuleBarrierRegistry(func() *qrdbsdk.BarrierRegistry { return node.BarrierRegistry() }),
    xkmssdk.WithServiceModulePINBackend(pinBackend),
    xkmssdk.WithServiceModuleCA(caConfig),               // *xkmssdk.TrustedCAMultiIdentityConfig
    xkmssdk.WithServiceModulePlatformSealer("tpm2", tpmSealer),
    xkmssdk.WithServiceModulePCRReader(pcrReader),
)
serverOpts = append(serverOpts, qrdbsdk.WithModule(module))
```
