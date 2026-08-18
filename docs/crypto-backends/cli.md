# Crypto Backends — CLI

> **Status: NORMATIVE** · Feature: `crypto-backends` · Repo: `go-xkms` · Last verified: 2026-08-19

Backends have no command group of their own. They are **selected** by the
global `--backend` flag on `xkmsctl` and **inspected** through the `backends`
and `algorithms` verbs, both documented in
[`../key-management/cli.md`](../key-management/cli.md).

## Selecting a backend

```
xkmsctl --backend tpm2   key generate node-idevid --key-algorithm ecdsa --curve P-256
xkmsctl --backend pkcs11 key list --pkcs11-module /usr/lib/softhsm/libsofthsm2.so --pkcs11-slot 0
xkmsctl --backend awskms key generate app-signing --key-algorithm rsa --key-size 3072
```

`--backend` defaults to `software`. `--key-dir` (default `xkms-data/keys`)
applies to file-based backends only.

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

## Backend-specific global flags

| Flag | Applies to | Purpose |
|---|---|---|
| `--pkcs11-module` | `pkcs11` | Path to the Cryptoki `.so` |
| `--pkcs11-slot` | `pkcs11` | Slot number (default `0`) |
| `--pkcs11-pin` | `pkcs11` | User PIN |
| `--so-pin` | `pkcs11`, `tpm2` | Security-officer PIN |
| `--key-dir` | `software`, `pkcs8` | Key directory |

Cloud backends take no CLI credentials — they read the provider's own
environment on the **server** side. Passing credentials on a command line would
put them in shell history and process listings.

## Build-tag reality

A backend that was not compiled in is not selectable. If `--backend vault`
reports the backend as unavailable, the binary was built without the `vault`
tag; see [`engineering.md`](engineering.md) §Configuration for the tag set, and
rebuild rather than working around it.

```
make build                 # BUILD_TAGS assembled from the make variables
xkmsctl backends list      # confirms what this binary actually has
```

## Parity coverage

`backends-list` has a `CommandDefinition` in
`test/integration/api/commands/commands.go` and runs on every protocol.
**Defect:** `backends get` and `algorithms` have no definition — see the note in
[`../key-management/cli.md`](../key-management/cli.md).
