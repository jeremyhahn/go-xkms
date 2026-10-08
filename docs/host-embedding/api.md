# Host Embedding — API

> **Status: NORMATIVE** · Feature: `host-embedding` · Repo: `go-xkms` · Last verified: 2026-10-04

Host embedding adds no wire endpoints. It makes the existing xkms surfaces
answer on a host that mounts the `xkms` ServiceModule:

| Surface | REST | gRPC (`xkms.v1.KeystoreService`) | Enabled by |
|---|---|---|---|
| Password Manager | `/api/v1/passwords/*` | `Password*` | `WithQRDBClient` (+ `WithBarrierRegistry`, `WithPINBackend` for tenant stores) |
| SSH | `/xkms/v1/ssh/*` | `SSH*` | `WithQRDBClient` |
| Certificate Authority | `/api/v1/ca/*` | `GetCACertificate`, `SignCSR`, … | `WithCA` + `WithQRDBClient` |
| Platform sealed secrets | `/api/v1/platform/*` | `SealStore*` | `WithPlatformSealer` + `WithQRDBClient` |
| TPM policies | `/api/v1/tpm/*`, `/api/v1/tenants/{id}/tpm*`, `/api/v1/keys/{id}/tpm-policy` | `TPMPolicy*`, `TPMObjectPolicy`, `*TenantTPMMode`, `TenantVTPM*` | a `tpm2` backend in the XKMSService + `WithQRDBClient` (`WithVTPM` for vtpm mode) |
| Backend credentials | `/api/v1/credentials/*` | — | always (`manual`), `WithCredentialStrategy` |
| PIN management | `/api/v1/pin/*` (`pin:read` to verify or read lockout, `pin:write` to set, change or reset) | `*PIN*` | `WithPINBackend` |

Authorization is unchanged: each route and RPC carries its `resource:action`
permission and is enforced by the host's qrdb authorizer. Platform-scoped
surfaces (platform store, tenant TPM modes, PIN management) refuse
tenant-scoped callers.

Status codes on a self-built module:

- **503** until the host's XKMSService is composed, and for a feature whose
  subsystem is reached only through the service and is off ("not configured").
- **501** for a route whose handler family is not mounted (e.g. the CA without
  `WithCA`, passwords without storage).

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
    xkmssdk.WithServiceModuleVTPM(vtpmConfig),          // *xkmssdk.TPMVTPMConfig; optional
)
serverOpts = append(serverOpts, qrdbsdk.WithModule(module))
```

The host's request chain around the node uses the same xkms pieces xkmsd
uses (see [engineering.md](engineering.md#host-request-chain-sdkgo)):

```go
live := xkmssdk.NewLiveAuthenticator(hostTokenAuthenticator) // an xkmssdk.Authenticator
nodeOpts = append(nodeOpts, node.WithAuthenticators(xkmssdk.NewQRDBBearerAuthenticator(live)))

limiter := xkmssdk.NewIPRateLimiter(&xkmssdk.IPRateLimitConfig{Enabled: true, RequestsPerMinute: 600})
defer limiter.Stop()
proxies, err := xkmssdk.ParseTrustedProxies([]string{"10.0.0.0/8"})
handler = xkmssdk.CorrelationMiddleware()(xkmssdk.IPRateLimitMiddleware(limiter, proxies)(handler))
```
