# Post-Quantum Cryptography — User Guide

> **Status: NORMATIVE** · Feature: `post-quantum` · Repo: `go-xkms` · Last verified: 2026-09-24

## What you can do today, and how

| I want to... | Path |
|---|---|
| See which PQC algorithms a server supports | `xkmsctl algorithms` — see [`cli.md`](cli.md) |
| Generate and use an ML-DSA or ML-KEM key from a client/server deployment | Not available yet over REST/gRPC/QUIC/MCP/`xkmsctl` — see [`api.md`](api.md) |
| Generate and use an ML-DSA or ML-KEM key today | Embed go-xkms as a Go library (below), or go through the PKCS#11 module — see [`../pkcs11-provider-module/user.md`](../pkcs11-provider-module/user.md) |
| Get SLH-DSA, HSS/LMS, or XMSS | Not implemented anywhere in this repository |

## Check what a server supports

```
xkmsctl --server https://kms.example.com:8443 algorithms
```

Entries tagged `[post-quantum]` are ML-DSA-44/65/87 (signing) and
ML-KEM-512/768/1024 (key encapsulation), sourced from the server's compiled-in
backends. This does not create a key or tell you whether the server exposes a
way to create one — see the next section.

## Generate and use a post-quantum key (embedded Go)

There is no `xkmsctl key generate --key-algorithm ML-DSA-65` today; the
generic key-generation verb only recognizes RSA/ECDSA/Ed25519 and the
symmetric AEAD algorithms (see [`cli.md`](cli.md)). The supported path is to
import go-xkms directly:

```go
package main

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/quantum"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func main() {
	backend, err := quantum.New(storage.New())
	if err != nil {
		panic(err)
	}
	defer backend.Close()

	ctx := context.Background()
	attrs := &types.KeyAttributes{
		CN: "signing-key",
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithm("ML-DSA-65"),
		},
	}

	priv, err := backend.GenerateKey(ctx, attrs)
	if err != nil {
		panic(err)
	}
	signer := priv.(*quantum.MLDSAPrivateKey)
	sig, err := signer.Sign(nil, []byte("message"), nil)
	fmt.Println(sig, err)
}
```

Swap `Algorithm` for `"ML-KEM-768"`, `"ML-KEM-1024"`, or `"ML-KEM-512"` (the
last refuses to construct under `GODEBUG=fips140=only` — see
[`architecture.md`](architecture.md) §"Why FIPS mode splits by parameter
set") and use `*quantum.MLKEMPrivateKey.Encapsulate`/`Decapsulate` instead of
`Sign`/`Verify`.

Storage above is `storage.New()` (in-memory); swap in any other
`storage.Backend` implementation for keys that must survive a restart. The
seed-based AEAD safety tracker `QuantumBackend` uses internally for
`MLKEMPrivateKey.Encrypt`/`Decrypt` is in-memory only regardless — see
[`engineering.md`](engineering.md) before relying on nonce-reuse detection
across a restart.

## FIPS-mode deployments

Under `GODEBUG=fips140=only`:

- ML-DSA-44/65/87 and ML-KEM-768/1024 keep working — they are the Go
  Cryptographic Module's own implementation.
- ML-KEM-512 refuses to construct at all (`quantum.mlkem512.ErrFIPSMode`),
  because it depends on `cloudflare/circl`, which the FIPS module boundary
  cannot see or certify. If your deployment must run FIPS-only, do not
  select ML-KEM-512; use ML-KEM-768 or ML-KEM-1024 instead.
- SLH-DSA/HSS/XMSS were never available in the first place, in or out of
  FIPS mode.

## If you need SLH-DSA, HSS/LMS, or XMSS

None of these are implemented in this repository today — not in the Go
primitives, not in the PKCS#11 module (its mechanism constants exist for
protocol conformance and refuse at `*Init`; see
[`architecture.md`](architecture.md)). File a gap against this project rather
than adding a private implementation downstream — see this repository's
no-cruft policy in `CLAUDE.md`.
