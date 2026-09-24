# Post-Quantum Cryptography — API

> **Status: NORMATIVE** · Feature: `post-quantum` · Repo: `go-xkms` · Last verified: 2026-09-24

Transport shapes in general are described once in
[`../key-management/api.md`](../key-management/api.md) §"How the six
transports are shaped". This document covers what is specific to PQC:
**there is no REST, gRPC, QUIC, or MCP surface for post-quantum key
generation or operations.**

## Capability matrix

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded (Go) | PKCS#11 module |
|---|---|---|---|---|---|---|
| List/discover PQC algorithms | `GET /api/v1/algorithms` (`RouteAuthPublic`) | same RPC shape | same | `xkms.algorithms` | `pkg/api/transport/embedded.Transport.Algorithms` | `C_GetMechanismList` / `C_GetMechanismInfo` |
| Generate ML-DSA-44/65/87 key | **absent** | **absent** | **absent** | **absent** | `quantum.New(store).GenerateKey(ctx, attrs)` with `attrs.QuantumAttributes.Algorithm` set | `C_GenerateKeyPair(CKM_ML_DSA_KEY_PAIR_GEN)` |
| Generate ML-KEM-512/768/1024 key | **absent** | **absent** | **absent** | **absent** | same, `IsKEM()` branch | `C_GenerateKeyPair(CKM_ML_KEM_KEY_PAIR_GEN)` |
| ML-DSA sign/verify | **absent** | **absent** | **absent** | **absent** | `MLDSAPrivateKey.Sign`/`Verify` | `C_SignInit(CKM_ML_DSA)` / `C_VerifyInit` |
| ML-KEM encapsulate/decapsulate | **absent** | **absent** | **absent** | **absent** | `MLKEMPrivateKey.Encapsulate`/`Decapsulate` | `C_EncapsulateKey(CKM_ML_KEM)` / `C_DecapsulateKey` |
| SLH-DSA / HSS / XMSS (any operation) | **absent** | **absent** | **absent** | **absent** | **absent** — no `pkg/quantum` package | **absent** — mechanisms declared, refused at `*Init` (see [`architecture.md`](architecture.md)) |

"Embedded (Go)" is not a network transport: it means constructing
`*pkg/keyprovider/quantum.QuantumBackend` inside a Go process that imports
`github.com/jeremyhahn/go-xkms`, either directly
(`quantum.New(storage.New())`) or through the SDK re-export
(`sdk/go/backends_quantum.go`: `xkms.NewQuantumBackend`,
`xkms.QuantumBackendConfig`). It requires no daemon and no authentication of
its own — the caller *is* the process holding the key.

## Why REST/gRPC generation is absent, precisely

The generic `POST /api/v1/keys` handler
(`pkg/api/rest/handlers.go:241-360`, `GenerateKeyHandler`) parses
`req.Algorithm` two ways only: as `types.ParseKeyAlgorithm` (an
`x509.PublicKeyAlgorithm` — RSA, ECDSA, Ed25519) or, if that fails, as a
`types.SymmetricAlgorithm` cast. There is no third branch that constructs a
`types.QuantumAttributes` or recognizes an ML-DSA/ML-KEM algorithm string.
`grep -rn QuantumAttributes pkg/api pkg/xkms cmd/xkmsctl` returns nothing.
The same absence holds for `pkg/api/grpc/service.go`. Reaching the quantum
backend over any of xkmsd's network transports would require adding that
branch and a corresponding request field — go-xkms does not ship it today.

## Discovery: `Algorithms`

The one PQC-aware call every transport does carry is algorithm discovery,
consumed by `xkmsctl algorithms` (see [`cli.md`](cli.md)). Each entry is a
`client.AlgorithmInfo` with a `PostQuantum bool` field
(`cmd/xkmsctl/algorithms.go:83-101` reads `a.PostQuantum`); it reports
availability, not a generation capability.

## Embedded Go usage

```go
import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/quantum"
)

backend, err := quantum.New(storage.New())
if err != nil {
	// handle
}
defer backend.Close()

attrs := &types.KeyAttributes{
	CN: "my-ml-dsa-key",
	QuantumAttributes: &types.QuantumAttributes{
		Algorithm: types.QuantumAlgorithm("ML-DSA-65"),
	},
}
priv, err := backend.GenerateKey(context.Background(), attrs)
```

`priv` is a `*quantum.MLDSAPrivateKey` (or `*quantum.MLKEMPrivateKey` for a
KEM algorithm); see [`engineering.md`](engineering.md) for the full method
set. The SDK re-export path (`sdk/go/backends_quantum.go`) is identical, only
importing the types under the `xkms.` prefix instead of `quantum.`.

## PKCS#11 module

The full mechanism-to-route mapping (`CKM_ML_DSA*`, `CKM_ML_KEM*`, the
refused `CKM_SLH_DSA*`/`CKM_HSS*`/`CKM_XMSS*` family) belongs to
[`../pkcs11-provider-module/api.md`](../pkcs11-provider-module/api.md), which
documents the module's full `C_*` surface; this document does not repeat it.
