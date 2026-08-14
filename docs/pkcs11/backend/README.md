# PKCS#11 Client Backend

`pkg/backend/pkcs11` is xkms acting as a **PKCS#11 client**: it loads somebody
else's Cryptoki library (SoftHSM2, YubiKey, nShield, CloudHSM, ...) and keeps
real production key material inside that device.

## Do not confuse the three PKCS#11 layers

This repository contains three separate things with "pkcs11" in the name. They
share a specification and nothing else. Conflating them has already caused
production damage — two Makefile targets were both named
`integration-test-pkcs11`, `make` took the last definition, and the SoftHSM
client suite silently never ran (see the comment at `Makefile:3470`).

| Layer | Code | Direction | Docs | Client suite |
|---|---|---|---|---|
| **Module** | `pkg/pkcs11/module`, `cmd/pkcs11-module` | xkms **PROVIDES** a `.so` to OpenSSL/OpenSSH/NSS | [`../module/`](../module/README.md) | `make integration-test-pkcs11-module-all` |
| **Client / backend** | `pkg/backend/pkcs11` | xkms **CONSUMES** somebody else's HSM | this directory | `make integration-test-pkcs11-backend` |
| **Manager** | `pkg/pkcs11/manager` | slot/token lifecycle (init, PIN, probe) | [`../manager.md`](../manager.md) | — |

A green run of one says nothing about the others. `make
integration-test-xkey-pkcs11` is a fourth, unrelated target: it runs xkey's
FIDO2/PIV consumer tests.

## Build tag

Every file in `pkg/backend/pkcs11` is guarded by `//go:build pkcs11`, and cgo is
required (the package binds `github.com/miekg/pkcs11`). Without the tag,
`pkg/server/backend_pkcs11_stub.go` logs a warning and the backend is absent:

```go
// initPKCS11Backend is a stub when PKCS#11 support is not compiled in
func (s *Server) initPKCS11Backend() error {
	if s.config.Backends.PKCS11 != nil && s.config.Backends.PKCS11.Enabled {
		s.logger.Warn("PKCS#11 backend enabled in config but not compiled in (use -tags pkcs11)")
	}
	return nil
}
```

## Quick start (SoftHSM2, what CI uses)

```bash
softhsm2-util --init-token --slot 0 --label 'test-token' --so-pin 1234 --pin 1234
```

```yaml
backends:
  pkcs11:
    enabled: true
    library: "/usr/lib/softhsm/libsofthsm2.so"
    token: "test-token"
    pin: "1234"
```

```bash
go build -tags pkcs11 ./cmd/xkmsd
```

## Contents

- [architecture.md](architecture.md) — the `Backend` contract, session pool, key addressing
- [configuration.md](configuration.md) — every config field, where it comes from, PIN handling
- [operations.md](operations.md) — key/sign/symmetric/ECDH/seal/attest operations and mechanisms
- [security.md](security.md) — CKA_SENSITIVE / CKA_EXTRACTABLE, what the wrap ceremony exposes
- [runbook.md](runbook.md) — pointing xkms at a real HSM, verification, failure modes

> `docs/backends/pkcs11.md` predates the removal of the `crypto11` wrapper and
> describes an API (`Config.LibraryPath`, `SlotID`, `SharedContext`,
> `store.Close(ctx)`, `backend.KeyParams`) that no longer exists. The pages in
> this directory are generated from the current source and supersede it.
