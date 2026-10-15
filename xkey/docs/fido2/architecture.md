# FIDO2 Daemon and GUI Device Host — Architecture

> **Status: NORMATIVE** · Feature: `fido2` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

## Boundary with `virtual-authenticator`

This folder and [`../virtual-authenticator/`](../virtual-authenticator/architecture.md)
both touch `pkg/fido2/authenticator`, and the split is deliberate rather than an
oversight:

- **`virtual-authenticator`** owns the CTAP2 authenticator as a product
  surface — what it is, the `xkey fido2` / `xkey uhid` flags that configure
  it, and the top-level trust model. Read it first.
- **`fido2`** (this folder) owns two things `virtual-authenticator` does not:
  the **process that hosts** the authenticator — the CLI daemon
  (`xkey/cmd/xkey/cmd/fido2.go`'s `fido2Device`) and the GUI's parallel host
  (`xkey/pkg/gui/services`) — and the **protocol-level depth** beneath the
  authenticator's CLI surface: the PIN protocol wire format, the hmac-secret
  extension protocol, credential-management enforcement, and the Security
  Officer / tamper-lock security analysis. That depth used to live in this
  same folder under `authenticator-security.md`, `authenticator-architecture.md`
  and `authenticator-overview.md`; those files are gone, and what was still
  true is now in [`engineering.md`](engineering.md).

Neither folder repeats the other's tables. Where you land first, look for a
link before assuming the fact is missing.

## The problem

`xkey fido2` has to be more than a CTAP2 implementation to be useful: a
browser needs it to show up as a USB device, a script needs a way to answer a
touch prompt without a person present, and the desktop GUI needs to run the
exact same authenticator inside its own process instead of shelling out to a
second binary. None of that is CTAP2 — it is process wiring, IPC, and two
different lifecycles for the same engine.

## Shape chosen: one authenticator engine, two hosts

`pkg/fido2/authenticator.Authenticator` (documented in
[`virtual-authenticator/engineering.md`](../virtual-authenticator/engineering.md))
is constructed once and driven by whichever process is running it:

| Host | Where | Front end |
|---|---|---|
| CLI daemon | `fido2Device` in `xkey/cmd/xkey/cmd/fido2.go:634` | `pkg/fido2/uhid.Device` + `authenticator.CTAPHIDHandler`, or the CDP bridge under `--cdp` |
| GUI | `pkg/gui/services.FIDO2DeviceService` | `pkg/fido2/virtualdevice.NativeVirtualDevice`, which wraps the same UHID + CTAPHID pieces for the Wails app |

Both hosts hold the same kind of moving parts — a UHID device, a presence
handler, a notifier — but they are two independent Go processes with two
independent authenticator instances. Running both against the same data
directory is a configuration mistake, not a supported multi-front-end mode:
each gets its own PIN state and its own credential store view, and whichever
one currently holds `/dev/uhid` is the one a browser actually talks to.

The GUI additionally runs `pkg/gui/services.FIDO2Service`, a management-plane
service with no UHID involvement at all — it lists and deletes credentials,
reads and writes RP policy, and selects which `keybackend.CompositeBackend`
member the authenticator signs with. It is the model behind the GUI's FIDO2
settings screen, not a second authenticator.

Rejected alternative: **one shared background service that both the CLI and
the GUI attach to.** Rejected because xkey has no privileged system service to
put it in — the CLI daemon runs as whatever invoked `sudo`, and the GUI runs
as the logged-in user's desktop session. Two hosts of the same engine is
simpler than inventing a third process to own it.

## Component boundaries

| Piece | Package | Role |
|---|---|---|
| CLI daemon composition | `xkey/cmd/xkey/cmd/fido2.go` (`fido2Device`) | Owns the UHID device, IPC server, keyboard, password store, notifier and CDP bridge for one foreground process |
| IPC transport | `xkey/pkg/ipc` | Unix socket serving `touch`, `unlock`, `status`, `autofill`, `pkcs11`, `pairing`, `state` messages; this folder covers the FIDO2-relevant subset |
| Notifications | `xkey/pkg/notify` | Tells a human a touch is pending: D-Bus, a custom command, a log line, or the GUI's own event bus |
| Virtual keyboard | `xkey/pkg/keyboard` | Types a stored password into whatever has focus, on `xkey touch --password` |
| GUI device host | `xkey/pkg/gui/services` (`FIDO2DeviceService`, `FIDO2Service`) | Runs the authenticator inside the Wails app; manages credentials and RP policy for the GUI |
| GUI UHID bridge | `pkg/fido2/virtualdevice` | `NativeVirtualDevice`: the GUI's equivalent of the daemon's `uhidDevice` + `hidHandler` pair |
| CTAP2 authenticator | `pkg/fido2/authenticator`, `pkg/fido2/uhid` | Owned by [`virtual-authenticator`](../virtual-authenticator/architecture.md) |
| Attestation identity provisioning | `xkey/cmd/xkey/cmd/fido2_provision_attestation.go` | CLI verb that turns on real attestation; talks to the xkms enterprise CA over `sdk/go/transport` |

## Data flow

### CLI daemon

```
sudo xkey fido2 --backend tpm2 --notify dialog
   │
   ├── uhidDevice + hidHandler ──► browser sees a USB security key
   ├── auth (authenticator.Authenticator) ──► CTAP2, per virtual-authenticator
   ├── ipcServer ──► $XDG_RUNTIME_DIR/xkey/xkey.sock
   │      ▲
   │      │  xkey touch / xkey unlock / xkey fido2 status / browser extension
   ├── socketHandler ──► turns an "xkey touch" into a CTAP2 presence answer
   ├── notifier ──► tells a human a touch is pending
   └── keyboard + pwStore ──► "xkey touch --password NAME" types a password
```

### GUI

```
Wails app starts
   │
   ├── FIDO2DeviceService.Start(storage, notifier)
   │      ├── constructs virtualdevice.NativeVirtualDevice (UHID + CTAPHID)
   │      ├── AttachPresenceHandler installs a SocketHandler, saving the
   │      │   authenticator's prior handler in priorUPHandler
   │      └── ApproveTouchRequest / DenyTouchRequest answer it from the UI
   └── FIDO2Service
          ├── ListCredentials / GetCredential / DeleteCredential
          ├── ListRPPolicies / GetRPPolicy / SetRPPolicy / DeleteRPPolicy
          └── ListKeyBackends / SetDefaultBackend (keybackend.CompositeBackend)
```

`FIDO2DeviceService.Stop` restores `priorUPHandler`, so stopping the UHID
bridge does not leave the shared authenticator instance without a presence
handler for other in-process consumers (autofill, the browser-extension
ceremony) — see the presence-handler invariant in
[`engineering.md`](engineering.md).

## Trust boundaries

- **The IPC socket is a local Unix socket, not a network API.** Its access
  control is filesystem permissions on
  `$XDG_RUNTIME_DIR/xkey/xkey.sock`. Anything that can open the socket file
  can call `touch` and `unlock`.
- **`xkey unlock` spends a retry budget independent of the PIN backend's
  own counter.** A wrong PIN over this verb is counted against 8 attempts;
  exhausting it refuses outright until a Security Officer resets it. See
  [`cli.md`](cli.md#xkey-unlock).
- **Attestation provisioning is Security Officer-gated**, and the private key
  never leaves the device: `provision-attestation` builds a PKCS#10 request
  on-device, sends only the request to the CA, and installs the returned
  chain. The CA never sees the private key, and a device with no SO PIN set
  cannot provision one at all (`ErrAttestProvisionSOPINNotSet`).
- **Tamper lock is a startup-time, fail-closed control, not a runtime
  toggle.** If the SO-signed policy HMAC does not verify when the
  authenticator opens, every user-mode CTAP command is refused until the SO
  re-signs the policy and the process restarts — no in-process call clears
  it. Detail: [`engineering.md#tamper-lock`](engineering.md#tamper-lock).
- **The GUI and the CLI daemon are not meant to run at once.** Neither
  process refuses to start because the other is running; they simply end up
  as two authenticators with two PIN states pointed at whichever storage
  each was configured with. Running one, deliberately, is the supported
  shape.

## What this feature deliberately does not do

- **It is not the CTAP2 authenticator.** Commands, extensions, PIN
  establishment, credential storage and the `xkey fido2`/`xkey uhid` flag
  reference are [`virtual-authenticator`](../virtual-authenticator/architecture.md).
- **It is not the headless WebAuthn ceremony driver.** `xkey auth
  register`/`login` are [`headless-webauthn`](../headless-webauthn/architecture.md).
- **It is not the phone pairing protocol.** The phone bridge behind
  `FIDO2Service.StartPhoneBridge` and `--backend phone` is
  [`phone-hsm`](../phone-hsm/architecture.md).
- **It is not the relying party.** Verification is
  [`go-xkms/pkg/webauthn`](../../../docs/webauthn/architecture.md).
