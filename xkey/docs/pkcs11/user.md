# PKCS#11 — User Guide

> **Status: NORMATIVE** · Feature: `pkcs11` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

## What this is

xkey can use a PKCS#11-compatible hardware token — a YubiKey, a SoftHSM2
software token for testing, or any HSM that ships a PKCS#11 shared
library — as the crypto backend for PIV certificates, SSH keys, and the
barrier's sealing strategy. There is no dedicated `xkey pkcs11` command:
you register and connect to a token through the desktop app, then select
`pkcs11` as the `--backend` on whichever CLI command you're using.

## Register and connect a token (GUI)

1. Open the xkey desktop app's PKCS#11 setup flow (Settings → Backends, or
   the setup wizard on first run).
2. Point it at a library path — `Detect YubiKey` finds `libykcs11.so` on
   common install paths automatically; a SoftHSM2 library
   (`libsofthsm2.so`) gets its token directory auto-configured if
   `SOFTHSM2_CONF` is not already set.
3. `Test Connection` validates the library and PIN against a chosen slot
   before you commit to it.
4. Registering the module persists it to the xkey config file, so it is
   available again after a restart without re-entering the library path.
5. `Connect` opens an authenticated session against the slot. A YubiKey
   requires its management key as the SO PIN for this step — key
   generation and certificate writes fail under the user PIN alone.

## Use the connected token

Once connected, `pkcs11` becomes a usable `--backend` value on:

```bash
# PIV certificates and key generation
xkey piv --backend pkcs11 --pkcs11-library /usr/lib/libykcs11.so \
  --pkcs11-token "YubiKey PIV" --pkcs11-pin 123456 status

# PIV-over-mTLS login
xkey auth login --server https://xkms.example.com:8443 --piv --slot 9c --backend pkcs11

# SSH keys
xkey ssh keys generate --name yubikey-ssh --type ecdsa-p256 --backend pkcs11

# Barrier sealing
xkey barrier init --strategy pkcs11

# Virtual CCID smartcard device backed by the token
xkey usb device start --device-backend pkcs11
```

Each of these takes the library path, token label, and PIN directly as
flags — you do not need the GUI running for the CLI to reach the token,
as long as the token itself is plugged in and the PIN is correct.

## When to use the GUI vs. the CLI

Use the **GUI** to discover and validate a token before committing to
it — probing slots, testing a PIN, and initializing a brand-new token (SO
PIN + user PIN) are interactive flows with no CLI equivalent. Use the
**CLI** once you already know the library path, token label, and PIN, for
scripted or headless PIV/SSH/barrier operations.

## Limitations

- **No IPC coverage for key generation or PIV certificate writes.** An
  external application that reaches xkey over its local IPC socket (the
  PKCS#11 module, a `crypto.Signer` helper) can only sign, list PIV slots,
  and read a PIV certificate through that socket — generating a key,
  writing a certificate, or any encrypt/decrypt/wrap/derive operation
  requires being in-process with xkey itself (the CLI, or `xkey usb
  device`). See [engineering.md](engineering.md#known-gaps).
- **Token initialization and slot browsing are GUI-only.** There is no
  `xkey pkcs11 init-token` or equivalent CLI verb.

## See also

- [CLI](cli.md) — every command that accepts `--backend pkcs11`
- [Architecture](architecture.md) — why the surface is split this way
- Root PKCS#11 module (for embedding xkey behind a system PKCS#11
  library): [`../../../docs/pkcs11-provider-module/user.md`](../../../docs/pkcs11-provider-module/user.md)
