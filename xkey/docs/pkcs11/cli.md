# PKCS#11 — CLI

> **Status: NORMATIVE** · Feature: `pkcs11` · Module: `go-xkms/xkey` · Last verified: 2026-10-09

Binary: `xkey`. **There is no `xkey pkcs11` command.** PKCS#11 is a backend
choice accepted by several otherwise-unrelated commands. Every flag below
is copied verbatim from its `cobra.Command` definition.

## `xkey piv` — PKCS#11-backed PIV certificate storage and key generation

`xkey piv`'s persistent flags (inherited by every `piv` subcommand:
`list`, `show`, `store`, `delete`, `export`, `status`):

| Flag | Default | Description |
|---|---|---|
| `--backend` | `software` | Key backend: `software`, `tpm2`, or `pkcs11` |
| `--piv-storage` | *(empty)* | Certificate storage type override: `file`, `tpm2`, or `pkcs11` (default: matches `--backend`) |
| `--storage-path` | *(default file path)* | Path for file storage |
| `--tpm-device` | *(default TPM device path)* | TPM device path for `tpm2` backend/storage |
| `--pkcs11-library` | *(default PKCS#11 library path)* | PKCS#11 library path |
| `--pkcs11-token` | *(empty)* | PKCS#11 token label |
| `--pkcs11-pin` | *(empty)* | PKCS#11 user PIN |
| `--pkcs11-so-pin` | *(empty)* | PKCS#11 Security Officer PIN (required for key generation) |

```bash
xkey piv --backend pkcs11 --pkcs11-library /usr/lib/libykcs11.so \
  --pkcs11-token "YubiKey PIV" --pkcs11-pin 123456 --pkcs11-so-pin 010203040506070801020304050607080102030405060708 \
  status

xkey piv --backend pkcs11 --pkcs11-library /usr/lib/libykcs11.so csr 9a --cn "user@example.com"
```

All eight flags are bound to viper (`piv.backend`, `piv.storage`,
`piv.storage_path`, `piv.tpm_device`, `piv.pkcs11_library`,
`piv.pkcs11_token`, `piv.pkcs11_pin`, `piv.pkcs11_so_pin`), so they may
also be set through the xkey config file under those keys, not only as
flags.

## `xkey auth login` — PIV-over-mTLS with a PKCS#11 slot

| Flag | Default | Description |
|---|---|---|
| `--piv` | `false` | Authenticate with a PIV slot certificate over mTLS instead of WebAuthn |
| `--slot` | `9a` | PIV slot to authenticate with (used with `--piv`) |
| `--backend` | `software` | PIV key backend: `software` or `pkcs11` (used with `--piv`) |

```bash
xkey auth login --server https://xkms.example.com:8443 --piv --slot 9c --backend pkcs11
```

A `--backend software` slot's private key exists only for the process
that generated it; `--backend pkcs11` reaches a real, persistent hardware
token, so it is the only PIV backend usable for a login from a later
process invocation.

## `xkey barrier init` — PKCS#11 HSM token as a sealing strategy

| Flag | Default | Description |
|---|---|---|
| `--strategy` | *(auto-detect)* | Sealing strategy: `software`, `tpm2`, `pkcs11` |

```bash
xkey barrier init --strategy pkcs11
```

This uses PKCS#11 to seal the barrier's root key, not to store xkms keys —
see [`../seal/`](../seal/) for the barrier itself. `xkey barrier` has no
`--pkcs11-library`/`--pkcs11-token`/`--pkcs11-pin` flags of its own; the
CLI barrier path resolves an HSM module from the platform configuration,
not from `barrier init` flags.

## `xkey ssh keys generate` — SSH keys on a PKCS#11 token

| Flag | Default | Description |
|---|---|---|
| `--backend` | *(server/embedded default)* | Crypto backend to generate the key on: `software`, `tpm2`, `pkcs11`, cloud |

```bash
xkey ssh keys generate --name yubikey-ssh --type ecdsa-p256 --backend pkcs11
```

See [`../ssh/cli.md`](../ssh/cli.md) for the rest of `xkey ssh keys`.

## `xkey usb device start` — PKCS#11-backed virtual CCID device

| Flag | Default | Description |
|---|---|---|
| `--device-backend` | *(default USB device backend)* | PKCS#11 backend: `software`, `tpm2`, or `pkcs11` |
| `--transport` | *(default transport)* | USB transport: `uhid` or `gadget` |
| `--udc` | *(empty)* | UDC controller name for gadget mode (auto-detect if empty) |

```bash
xkey usb device start --device-backend pkcs11
```

`start` picks the PKCS#11 transport from the local app access setting
(`usbDevicePKCS11Transport`, `cmd/xkey/cmd/usb_device.go`) and hands it to
`ccid.NewPKCS11Bridge`, which translates smartcard APDUs presented over
the virtual USB device into PKCS#11 operations — see
[architecture.md](architecture.md):

| Local app access | Transport | No GUI listening |
|---|---|---|
| off (default) | `pkcs11.EmbeddedTransport`: keys opened in this process | — |
| on | `pkcs11.IPCTransport`: the unlocked GUI's keys, over its socket | Fails with `ErrUSBDeviceGUINotListening` (wrapping `ErrIPCConnectionFailed`) |

It never falls back from one transport to the other. With the setting on,
open and unlock xKey first, or turn the setting off with `xkey app-access
disable`. Both transports carry every PKCS#11 transport operation, so the
same APDUs work either way; over IPC a sealed barrier fails each one.

## GUI-only: no CLI equivalent

Registering a PKCS#11 library, enumerating its slots, initializing a
token, and opening an authenticated session (`PKCS11Service` — see
[api.md](api.md)) are GUI-only operations reachable through the xkey
desktop app's PKCS#11 setup flow. There is no CLI verb for any of them;
the CLI paths above (`piv`, `auth login`, `ssh keys generate`, `usb
device start`) all take an already-known library path, token label, and
PIN as flags instead of walking an interactive registration flow.

## See also

- [Architecture](architecture.md) — why PKCS#11 has no `xkey pkcs11` verb
  group
- [API](api.md) — the GUI bindings and IPC wire protocol that do exist
- [User Guide](user.md) — task-oriented usage
