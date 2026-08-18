# PKCS#11 Provider Module — CLI

> **Status: NORMATIVE** · Feature: `pkcs11-provider-module` · Repo: `go-xkms` · Last verified: 2026-08-19

The module itself has **no CLI**: it is a `.so` that other programs load. Its
entire configuration surface is environment variables
([`engineering.md`](engineering.md) §Configuration).

Two CLIs are adjacent to it.

## Building and loading the module

```
CGO_ENABLED=1 go build -buildmode=c-shared -o build/lib/libxkms_pkcs11.so ./cmd/pkcs11-module
```

Then point any Cryptoki consumer at it:

```
export XKMS_PKCS11_MODE=local
export XKMS_PKCS11_LOCAL_KEYDIR=$XDG_DATA_HOME/xkms/pkcs11-keys
export XKMS_PKCS11_USER_PIN=…

pkcs11-tool --module ./build/lib/libxkms_pkcs11.so --list-slots
openssl pkeyutl -engine pkcs11 -keyform engine -sign -inkey "pkcs11:object=my-key" …
```

Remote mode is the default — omit `XKMS_PKCS11_MODE` and set
`XKMS_PKCS11_TARGET` instead.

## `xkmsctl pkcs11` — managing tokens, not the module

`cmd/xkmsctl/pkcs11.go`. These verbs operate on PKCS#11 tokens generally, which
includes third-party tokens used as a *backend*; they are not a control surface
for this module.

| Verb | Purpose |
|---|---|
| `pkcs11 probe` | Probe a module for capabilities |
| `pkcs11 register` | Register a module with the server |
| `pkcs11 list-modules` | List registered modules |
| `pkcs11 list-tokens` | List tokens visible through a module |
| `pkcs11 init-token` | Initialize a token |
| `pkcs11 connect` | Connect to a token |
| `pkcs11 disconnect` | Disconnect |

```
xkmsctl pkcs11 list-modules
xkmsctl pkcs11 list-tokens --pkcs11-module /usr/lib/softhsm/libsofthsm2.so
xkmsctl pkcs11 init-token --pkcs11-module /usr/lib/softhsm/libsofthsm2.so --pkcs11-slot 0
```

Global flags `--pkcs11-module`, `--pkcs11-slot`, `--pkcs11-pin` and `--so-pin`
apply — see [`../key-management/cli.md`](../key-management/cli.md).

## The two directions, so nobody wires it backwards

| You want | Use |
|---|---|
| **other software to use xkms keys** | build and load `libxkms_pkcs11.so` — this feature |
| **xkms to use a third-party token's keys** | `--backend pkcs11` — [`../crypto-backends/cli.md`](../crypto-backends/cli.md) |

Both involve PKCS#11 and they are opposites. Pointing `XKMS_PKCS11_TARGET` at a
token, or `--pkcs11-module` at `libxkms_pkcs11.so`, are the two ways to get this
wrong.

## Exit codes and diagnostics

The module has no exit code — it returns `CK_RV` values to its host. A consumer
reporting a bare hex code should be read against
`pkg/pkcs11/module/errors.go`; `CKR_FUNCTION_NOT_SUPPORTED` (`0x54`) means the
token will never do that operation, as opposed to the operation having failed.

A `C_Initialize` failure naming a backend usually means the module was built
without that backend's build tag, not that the environment is wrong
([`engineering.md`](engineering.md) §Configuration).

## Parity coverage

Not applicable to the module: the Cryptoki ABI is not one of the six transports
and the parity runner does not drive `.so` consumers. Coverage is
`cmd/pkcs11-module/*_test.go` — including the two-call idiom suite — plus
`test/integration/pkcs11`.

**Defect:** the `xkmsctl pkcs11` verbs have no `CommandDefinition` in
`test/integration/api/commands/commands.go`.
