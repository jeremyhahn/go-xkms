# Crypto Backends — CLI

> **Status: NORMATIVE** · Feature: `crypto-backends` · Repo: `go-xkms` · Last verified: 2026-10-11

Backends have no command group of their own. They are **selected** by the
global `--backend` flag on `xkmsctl` and **inspected** through the `backends`
and `algorithms` verbs, both documented in
[`../key-management/cli.md`](../key-management/cli.md).

## Selecting a backend

```
xkmsctl --backend tpm2   key generate node-idevid --key-algorithm ecdsa --curve P-256
xkmsctl --backend awskms key generate app-signing --key-algorithm rsa --key-size 3072
```

`--backend` defaults to `software`; `--key-dir` (default `xkms-data/keys`)
applies to file-based backends only (`cmd/xkmsctl/root.go:118-121`).

## Inspecting what a backend can do

```
xkmsctl backends list -o json
xkmsctl backends get tpm2 -o json
```

`backends get` returns the backend's `types.Capabilities` — `HardwareBacked`,
`Signing`, `Decryption`, `KeyRotation`, `SymmetricEncryption`, `Sealing`,
`Import`, `Export`, `KeyAgreement`, `ECIES`, `Attestation`, `QuantumSigning`,
`KeyEncapsulation`, `SecurityLevel`. Read this before scripting anything that
assumes a capability; the answer differs per deployment, not just per backend
type.

## Global flags that touch backends

| Flag | Purpose |
|---|---|
| `--backend` | Backend for the command (default `software`) |
| `--key-dir` | Key directory for file-based backends (default `xkms-data/keys`) |
| `--so-pin` | Security-officer PIN for privileged operations |

All three are persistent flags on the root command
(`cmd/xkmsctl/root.go:118-121`, `:157-158`). The `--pkcs11-module`,
`--pkcs11-slot` and `--pkcs11-pin` globals (`cmd/xkmsctl/root.go:160-166`) do
**not** select or configure the `pkcs11` backend: they load the client's mTLS
certificate from a hardware token, and are documented with the transport
flags.

Cloud backends take no CLI credentials — they read the provider's own
environment on the **server** side. Passing credentials on a command line would
put them in shell history and process listings.

## A backend that was not compiled in

`xkmsctl backends list` shows only what the server actually loaded. A
`pkcs11`, `awskms`, `gcpkms`, `azurekv` or `vault` section enabled in an
`xkmsd` built without that backend's tag is logged as a warning at start-up
and the backend is absent (`pkg/server/backend_vault_stub.go:19-24`); an
enabled `frost` section stops the server with a "not compiled in" error
(`pkg/server/backend_frost_stub.go:25-30`). Rebuild with the toggle on rather
than working around it; see [`engineering.md`](engineering.md)
§Configuration.

```
make build-full            # every WITH_* toggle on
make build WITH_VAULT=1    # or a single toggle (all default to 1)
xkmsctl backends list      # confirms what the server actually has
```

## Parity coverage

`backends-list` has a `CommandDefinition` in
`test/integration/api/commands/commands.go` and runs on every protocol.
**Defect:** `backends get` and `algorithms` have no definition — see the note in
[`../key-management/cli.md`](../key-management/cli.md).
