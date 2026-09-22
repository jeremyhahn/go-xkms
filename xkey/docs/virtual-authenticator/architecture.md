# Virtual FIDO2 Authenticator — Architecture

> **Status: NORMATIVE** · Feature: `virtual-authenticator` · Module: `go-xkms/xkey` · Last verified: 2026-09-21

## The problem

A hardware security key is a small computer that holds credentials and requires
a human touch. It is excellent, and it has three limitations: you have to buy
one, you have to carry it, and an agent or a CI job cannot touch it.

xkey's virtual authenticator **is** a FIDO2 authenticator — it presents itself
to the operating system as a USB HID device, so browsers and every WebAuthn
consumer treat it as real hardware. The credentials it holds live under xkey's
own protection: a TPM, a PKCS#11 token, a paired phone, or software.

This is the mirror image of [`go-xkms/pkg/fido2`](../../../docs/fido2-ctap2/architecture.md),
which *drives* an authenticator. Here xkey *is* one.

## Shape chosen: a CTAP2 implementation behind a UHID device

`xkey/pkg/uhid` creates a Linux UHID device — the kernel then presents it to
userspace as an ordinary USB HID authenticator. `xkey/pkg/authenticator`
implements the CTAP2 side of that wire:

| CTAP2 command | File |
|---|---|
| `authenticatorMakeCredential` | `cmd_makecredential.go` |
| `authenticatorGetAssertion` | `cmd_getassertion.go` |
| `authenticatorGetInfo` | `cmd_getinfo.go` |
| `authenticatorClientPIN` | `cmd_clientpin.go`, `pin_protocol.go`, `pin_protocol_v1.go` |
| `authenticatorCredentialManagement` | `cmd_credmgmt.go` |
| `authenticatorConfig` | `cmd_config.go` |
| `authenticatorReset` | `cmd_reset.go` |

Extensions: `ext_hmac_secret.go` (the derived-key extension) and
`ext_deviceconfig.go`.

Credential storage is behind a DAO seam — `dao_credential_store.go`,
`dao_rp_policy_store.go` — and key material behind
`key_manager.go`, `key_wrapper.go`, `keybackend/`. So *what the authenticator
is* (CTAP2 over UHID) is separate from *where its secrets live*, which is the
`--backend` choice.

Rejected alternatives:

- **A browser extension pretending to be an authenticator.** Rejected: it works
  only in that browser, and cannot serve `ssh`, `sudo`, or a system login.
- **Emulating a specific vendor's key.** Rejected: attestation would be a lie.
  xkey's attestation says what it is.
- **Holding credentials in a file only.** Rejected — the point is that the
  backend can be a TPM or a phone.

## Component boundaries

| Piece | Package |
|---|---|
| UHID device (Linux) | `xkey/pkg/uhid` (`uhid_linux.go`, `uhid_stub.go` elsewhere) |
| CTAP2 authenticator | `xkey/pkg/authenticator` |
| HID framing adapter | `xkey/pkg/authenticator/hid_adapter.go` |
| Key material backends | `xkey/pkg/authenticator/keybackend`, `key_manager.go`, `key_wrapper.go` |
| Credential and RP-policy stores | `dao_credential_store.go`, `dao_rp_policy_store.go` |
| Chrome DevTools bridge | `xkey/pkg/cdp` |
| Notification / user presence | `xkey/pkg/notify` |
| Reusable crypto and vault primitives | `go-xkms/pkg/*`, consumed via `go-xkms/sdk/go` |

Capability row: **"Virtual FIDO2/CTAP2 authenticator (Linux UHID USB HID
device)"** under the xkey product surface, owned by go-xkms.

The architecture rule between the two modules: reusable logic lands in
`go-xkms/pkg/*` and xkey consumes it through `go-xkms/sdk/go` only. xkey is a
shell around the stack, never a second implementation of it.

## Data flow

```
browser / ssh / sudo / any WebAuthn consumer
   │  (sees an ordinary USB HID authenticator)
   ▼
Linux UHID  ←→  xkey/pkg/uhid
   ▼
xkey/pkg/authenticator — CTAP2 commands, PIN protocol, extensions
   ├── user presence:  a handler named at construction (socket + xkey touch, terminal, auto-grant)
   ├── credentials:    DAO credential store
   └── key material:   key_manager → keybackend → software | tpm2 | pkcs11 | phone
```

`--cdp` adds a second front end: the Chrome DevTools virtual-authenticator
bridge, for driving browser tests without a real device on the bus.

## Trust boundaries

- **The authenticator is only as strong as its `--backend`.** `software` keeps
  credentials in xkey's own store; `tpm2` binds them to the machine; `phone`
  puts them in a paired device's TEE. The CTAP2 surface is identical, so a
  relying party cannot tell — which is what makes the choice yours to make
  honestly.
- **User presence is the security property, and the presence handler is
  where it lives.** The authenticator refuses to construct without one; the
  daemon installs a socket handler answered by a dialog or `xkey touch`, or a
  terminal handler under `--interactive`. Programmatic devices
  (`xkey/pkg/virtualdevice`, the CDP bridge) name an auto-grant handler at
  their own construction site, so the decision to drop the human is visible
  in the code that made it, never a default.
- **User verification is never asserted, only performed.** The UV flag is set
  when a PIN was verified in the ceremony or the key backend verified a human
  itself (a paired phone's biometric). The flag that once reported built-in
  verification so a browser would skip its PIN dialog was removed: it turned
  "a person verified themselves" into "this machine had its key material".
- **`--require-touch` defaults to true.** Turning it off skips the touch only
  after a verified PIN; a ceremony with no PIN still asks for presence.
- **`--attestation` decides what the authenticator says about itself.** It does
  not claim to be someone else's hardware.
- **The PIN protects the authenticator, not the machine.** `--unified-pin`
  (default true) propagates the host PIN service's user PIN to this
  authenticator's own CTAP2 PIN hash (it does not synchronize a separate
  PKCS#11 or file PIN store — go-xkms has exactly one governing PIN backend
  per device, see go-xkms#307), which is a usability decision with a
  blast-radius consequence: the one PIN a person types opens both.
- **`--cdp` opens a bridge to a Chrome debugging port** (default `9222`).
  Anything that can reach that port can drive the authenticator.

## What this feature deliberately does not do

- **It does not claim to be hardware it is not.**
- **It is not the relying party.** Verification is
  [`go-xkms/pkg/webauthn`](../../../docs/webauthn/architecture.md).
- **It does not drive other authenticators** — that is
  [`go-xkms/pkg/fido2`](../../../docs/fido2-ctap2/architecture.md).
- **It is Linux-only for the UHID path.** `uhid_stub.go` is the non-Linux build;
  the CDP bridge is the cross-platform route for browser testing.
