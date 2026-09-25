# PKCS#11 Backend — CLI

> **Status: NORMATIVE** · Feature: `pkcs11-backend` · Repo: `go-xkms` · Last verified: 2026-09-24

## There is no `xkmsctl pkcs11-backend` command group

The PKCS#11 backend has **no dedicated CLI verbs**. It is reached the same
way every other crypto backend is: the global `--backend` persistent flag on
`xkmsctl` (default `software`, `cmd/xkmsctl/root.go:111`:
`"backend to use (software, pkcs11, tpm2, awskms, gcpkms, azurekv, vault)"`),
which flows into every `xkmsctl key ...` request as `cfg.Backend`
(`cmd/xkmsctl/key.go`, every `Backend: cfg.Backend` field).

```bash
xkmsctl --backend pkcs11 key generate my-hsm-key \
  --key-type signing --key-algorithm ecdsa --curve P-256
xkmsctl --backend pkcs11 key list
xkmsctl --backend pkcs11 key get my-hsm-key
xkmsctl --backend pkcs11 key sign my-hsm-key --data-file payload.bin
xkmsctl --backend pkcs11 key delete my-hsm-key
```

See [`../key-management/cli.md`](../key-management/cli.md) for the full
`xkmsctl key ...` verb reference — every verb there works against
`--backend pkcs11` exactly as it does against `software`; this backend adds
no PKCS#11-specific flags to any of them.

## Do not confuse this with `xkmsctl pkcs11 ...`

`cmd/xkmsctl/pkcs11.go` registers a **separate** `xkmsctl pkcs11` command
group — `probe`, `register`, `list-modules`, `list-tokens`, `init-token`,
`connect`, `disconnect`. It talks to `sdk/go/pkcs11/manager` (the
slot/token-lifecycle **manager** layer — see the three-layer table in
[`architecture.md`](architecture.md)), not to `pkg/backend/pkcs11` (this
feature). Its `init-token`/`connect` verbs are the local token-provisioning
and probing workflow that layer owns; they do not generate, list, or use
xkms keys, and using them does not require or imply `-tags pkcs11` in the
`xkmsctl` binary. It is documented as part of
[`../pkcs11-provider-module/cli.md`](../pkcs11-provider-module/cli.md), not
here.

## Preparing a token before pointing `xkmsctl`/`xkmsd` at it

`xkmsd` never initializes a token itself — see
[`architecture.md`](architecture.md) §"Lifecycle". Do it once with vendor
tooling before the daemon starts:

```bash
softhsm2-util --init-token --slot 0 --label 'xkms' --so-pin 12345678 --pin 87654321
softhsm2-util --show-slots
```

or, for any device, generically:

```bash
pkcs11-tool --module /path/to/vendor.so --list-slots
pkcs11-tool --module /path/to/vendor.so --login --pin <PIN> --list-objects
```

## Round-tripping against a running daemon

```bash
xkmsctl --server https://kms.example.com:8443 --tls-ca ca.crt \
  --backend pkcs11 key generate demo-key --key-type signing --key-algorithm ecdsa --curve P-256
```

REST/gRPC/QUIC/unix callers not going through `xkmsctl` pass the backend as
a request parameter — see [`api.md`](api.md). Confirm on the device side
that the object exists and the private half is not readable:

```bash
pkcs11-tool --module /path/to/vendor.so --login --pin <PIN> --list-objects --type privkey
```
