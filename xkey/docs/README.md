# xKey Documentation

xKey is a unified security key interface that provides FIDO2/WebAuthn, OATH TOTP/HOTP, PIV certificates, SSH agent, OIDC authentication, and static password functionality. Unlike traditional hardware-only security keys, xKey works with **any go-xkms backend** -- from software storage to hardware HSMs to cloud KMS services.

## Feature documentation

Each feature below has a folder holding five documents — `architecture.md`,
`engineering.md`, `cli.md`, `api.md`, `user.md`. Together they are the
feature's requirements: read the folder before reading the code, and change
the folder in the same commit that changes the behavior.

**Add the row in the same commit that creates the folder.** An index updated in
a later sweep is wrong in between, and the reader who hits it in between cannot
tell.

| Feature | What it covers | Legacy path superseded |
|---------|----------------|------------------------|
| [agent](agent/) | Network agent enrollment, connection-time revocation checking, and removal | `agent/` |
| [agent-automation](agent-automation/) | PIN and touch automation for headless agents and CI | `agent/` |
| [browser-trust-injection](browser-trust-injection/) | Injecting xkey trust-store CA certificates into Chrome- and Firefox-family browsers via a pure-Go NSS `cert9.db` writer, isolated/shared profile modes, and Chrome extension import | [`../../docs/browser/README.md`](../../docs/browser/README.md) — stale on the Firefox mechanism; see `architecture.md` |
| [fido2](fido2/) | The `xkey fido2` daemon process, IPC-facing verbs (`touch`, `unlock`, `status`, `provision-attestation`), the GUI's FIDO2 device/service host, and a PIN/hmac-secret/SO-token protocol reference for `xkey/pkg/authenticator` | `fido2/README.md`, `fido2/overview.md`, `fido2/authenticator-*.md`, `fido2/daemon-*.md` (with `virtual-authenticator`) |
| [gui](gui/) | The Wails v2 desktop GUI: the `App` composition root, the ~44-service Wails-bound backend surface, the Unix-socket IPC server, events, and the Svelte frontend | `gui/architecture.md` (`gui/README.md`, `gui/features.md`, `gui/design-system.md`, `gui/setup-wizard.md`, `gui/api-explorer.md`, `gui/browser-settings.md`, `gui/ROADMAP.md` remain as superseded background) |
| [headless-webauthn](headless-webauthn/) | Programmatic WebAuthn ceremonies without a browser or a human | `fido2/` (with `virtual-authenticator`) |
| [luks](luks/) | LUKS2 encrypted storage: container lifecycle and the fail-closed lock gate shared by the CLI and GUI | `luks/README.md` |
| [autofill](autofill/) | Browser extension credential/TOTP autofill: native messaging, extension pairing, CTAP2 assertion verification, policy | `autofill/README.md`, `autofill/compliance.md`, `autofill/extension.md`, `autofill/policy.md` |
| [oath](oath/) | TOTP/HOTP credential management, QR scanning, barrier-backed storage | `oath/README.md` |
| [oidc](oidc/) | OpenID Connect relying-party login and the CLI's barrier-backed session token store | `oidc/` |
| [password](password/) | Static password storage, folders, browser-autofill metadata, xkmsd-backed session access modes | `password/README.md` |
| [phone](phone/) | The `xkey/pkg/phone` FIDO2 key backend (`--backend phone`), its BLE/USB/TCP transports, device-fingerprint continuity, the bidirectional xkmsd bridge, and the GUI's `PhoneService` | `phone/README.md`, `phone/protocol.md`, `phone/attestation.md`, `phone/bidirectional.md`, `phone/transport.md`, `phone/android/`, `phone/backend/` |
| [phone-hsm](phone-hsm/) | The phone-as-HSM backend and its pairing protocol | `phone/` |
| [pkcs11-manager](pkcs11-manager/) | The PKCS#11 module/token manager wrapper and its automatic per-slot backend-registry synchronization | — |
| [pkcs11](pkcs11/) | xkey's PKCS#11 side: GUI module/slot/token management, the embedded and IPC `PKCS11Transport` implementations, and the `--backend pkcs11` surface across other commands | `pkcs11/ipc.md` |
| [platform-trust](platform-trust/) | Trust bootstrap, the classified truststore, platform CA import | `architecture/server-registry.md` (trust half) |
| [seal](seal/) | The Barrier, barrier PCR-policy auto-unseal (shared by the CLI and GUI), the named PCR policy store, and the legacy sealed-blob store | `seal/README.md`, `seal/platform-policy.md`, `configuration/auto-unseal.md` (now a pointer) |
| [secret-service](secret-service/) | The `org.freedesktop.secrets` D-Bus daemon exposing the static-password store to secret-tool, git-credential-libsecret and browsers, with Lock/Unlock tied to the barrier | — |
| [setup-wizard](setup-wizard/) | First-run setup: quick and manual personal setup, enterprise SO provisioning and onboarding, and where the generated SO PIN may live | `gui/setup-wizard.md`, `seal/setup-wizard.md` |
| [share-custody](share-custody/) | The Shamir share custody client | — |
| [ssh](ssh/) | xkey's SSH key/profile/host-key management, connect/console, local `ssh_config`/agent discovery, and the GUI SSH services | `ssh/README.md` |
| [virtual-authenticator](virtual-authenticator/) | The virtual FIDO2/CTAP2 authenticator over Linux UHID | `fido2/` (with `headless-webauthn`) |

The core capabilities these build on live in the root module — the
[password vault](../../docs/password-vault/), the
[WebAuthn relying party](../../docs/webauthn/), the
[FIDO2/CTAP2 client](../../docs/fido2-ctap2/), [PIV](../../docs/piv-smartcard/)
and [trust bootstrap](../../docs/trust-bootstrap/). That split follows the rule
between the two modules: reusable logic lives in `go-xkms/pkg/*` and xkey
consumes it through `go-xkms/sdk/go`, so these folders document a product
surface rather than a second implementation.

Everything below this section predates the feature-folder convention. It is
**unconverted debt, not a precedent** — a new feature gets a five-file folder
regardless of what the rest of this tree looks like. While conversion is in
progress a feature folder is NORMATIVE for its feature and a superseded legacy
path is not; where they disagree, the feature folder wins.

Still owed a folder: `ble/`, `device/`, `piv/`, `usb/`, `xkeysigner/`. Not
features and staying as they are: `architecture/`, `configuration/`,
`roadmap/`, `testing/`, `usage/`.

## Documentation Structure

| Directory | Description |
|-----------|-------------|
| [agent/](agent/) | Agent enrollment and management |
| [architecture/](architecture/) | System architecture, internal design, and data stores |
| [ble/](ble/) | Bluetooth Low Energy transport and Android pairing |
| [configuration/](configuration/) | Application configuration and enterprise setup (see [seal/](seal/) for auto-unseal) |
| [device/](device/) | Device pairing, QR pairing, and TCP relay |
| [fido2/](fido2/) | The `xkey fido2` daemon process and GUI device host (converted; see [Feature documentation](#feature-documentation) above) |
| [gui/](gui/) | The Wails v2 desktop GUI: `App`, the Wails-bound service surface, IPC, events (converted; see [Feature documentation](#feature-documentation) above) |
| [luks/](luks/) | LUKS2 encrypted storage management |
| [oath/](oath/) | OATH TOTP/HOTP credential management with QR scanning |
| [oidc/](oidc/) | OpenID Connect authentication flows and provider management |
| [password/](password/) | Static password management with encryption and access modes |
| [phone/](phone/) | The `xkey/pkg/phone` FIDO2 key backend, its transports, and the GUI's `PhoneService` (converted; see [Feature documentation](#feature-documentation) above; pairing/protocol/CLI is [phone-hsm/](phone-hsm/)) |
| [piv/](piv/) | PIV smart card certificate management |
| [pkcs11/](pkcs11/) | xkey's PKCS#11 module/slot/token management, transports, and `--backend pkcs11` surface (five-file feature folder) |
| [roadmap/](roadmap/) | Feature roadmaps for media, PIV, and web |
| [seal/](seal/) | The Barrier, TPM PCR-policy auto-unseal, named PCR policies, and the legacy sealed-blob store |
| [secret-service/](secret-service/) | The `org.freedesktop.secrets` D-Bus Secret Service daemon |
| [ssh/](ssh/) | SSH agent with standalone and server modes |
| [ssh/](ssh/) | xkey's SSH key/profile/host-key/console management (five-file feature folder) |
| [testing/](testing/) | Testing guides and end-to-end test documentation |
| [usage/](usage/) | CLI usage guides, tutorials, and command reference |
| [usb/](usb/) | USB CCID smart card interface and disk image creation |
| [autofill/](autofill/) | AutoFill browser extension architecture and policy |
| [xkeysigner/](xkeysigner/) | crypto.Signer via IPC (daemon integration) |

## Skills and Tools

| Tool | Purpose |
|------|---------|
| [xkey-agent skill](../skills/xkey-agent/SKILL.md) | AI agent skill for CLI automation of status queries, key operations, certificate management, and agent services |

## Architecture

xKey operates in two modes:

1. **Standalone Mode** -- Uses local software or TPM backend directly
2. **xkmsd Mode** -- Communicates with the xkmsd service to use any configured backend

```
┌─────────────────────────────────────────────────────────────┐
│                      Applications                            │
│         (Browsers, SSH, Smart Cards, CLI tools)             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                         xKey                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │  FIDO2   │  │   OATH   │  │   PIV    │  │ Passwords│    │
│  │ WebAuthn │  │TOTP/HOTP │  │ Certs    │  │  Static  │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Virtual USB HID (UHID)                   │  │
│  │         Keyboard │ FIDO2 │ Smart Card                │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
            ┌─────────────────┴─────────────────┐
            ▼                                   ▼
┌───────────────────────┐           ┌───────────────────────┐
│   Standalone Mode     │           │   xkmsd Mode          │
│   (Local Backends)    │           │   (All Backends)      │
├───────────────────────┤           ├───────────────────────┤
│ • Software (memory)   │           │ • All Hardware HSMs   │
│ • Software (file)     │           │ • All Cloud KMS       │
│ • TPM 2.0             │           │ • Software backends   │
└───────────────────────┘           └───────────────────────┘
                                              │
                                              ▼
                                    ┌───────────────────────┐
                                    │      xkmsd            │
                                    │  (Key Mgmt Service)   │
                                    └───────────────────────┘
```

## Features

### Protocol Support
- **FIDO2/WebAuthn** -- Full CTAP2 implementation via USB HID
- **OATH** -- RFC 4226 (HOTP) and RFC 6238 (TOTP) with QR scanning
- **PIV** -- Smart card certificates
- **Static Passwords** -- YubiKey-style password typing via virtual keyboard
- **SSH** -- Agent mode with key management and git signing
- **OIDC** -- OpenID Connect with DPoP and AWS Console login

### Backend Support

| Backend | Type | Standalone | xkmsd |
|---------|------|------------|-------|
| Software (memory) | Software | Y | Y |
| Software (file) | Software | Y | Y |
| TPM 2.0 | Hardware | Y | Y |
| PKCS#11/HSM | Hardware | - | Y |
| YubiKey PIV | Hardware | - | Y |
| SmartCard-HSM | Hardware | - | Y |
| Nitrokey HSM | Hardware | - | Y |
| AWS KMS | Cloud | - | Y |
| GCP KMS | Cloud | - | Y |
| Azure Key Vault | Cloud | - | Y |
| HashiCorp Vault | Cloud | - | Y |

## Quick Start

### Building from Source

```bash
cd xkey && go build -o xkey ./cmd/xkey
```

### Requirements

- Linux kernel 4.2+ (UHID support)
- `/dev/uhid` accessible (root or udev rules)
- D-Bus session bus for desktop notifications (optional)

### Standalone Mode

```bash
# Software backend (testing/development)
sudo xkey fido2 --backend software

# TPM backend (hardware-backed)
sudo xkey fido2 --backend tpm2
```

### Phone Mode

```bash
# Keys stay in a paired Android phone's TEE/StrongBox
sudo xkey fido2 --backend phone
sudo xkey fido2 --backend phone --phone-device "John's Pixel"
```

### Unattended Mode

```bash
# A PIN-verified ceremony asks for no touch; the client supplies the PIN
# (xkey auth ... --pin-stdin, or Chrome's own PIN dialog)
sudo xkey fido2 --require-touch=false --notify none

# No /dev/uhid and no sudo — drive Chrome's virtual authenticator
xkey fido2 --cdp --cdp-port 9222
```

## Component Documentation

### [FIDO2](fido2/)

See the [Feature documentation](#feature-documentation) table above for the
five-file folder: [architecture](fido2/architecture.md),
[engineering](fido2/engineering.md), [cli](fido2/cli.md), [api](fido2/api.md),
[user](fido2/user.md). The CTAP2 authenticator itself — commands, PIN
establishment, credential storage, and the `xkey fido2`/`xkey uhid` flag
reference — is [virtual-authenticator](virtual-authenticator/).

### [Architecture](architecture/)
- [Overview](architecture/README.md) -- System architecture and component design
- [Platform Store](architecture/platform-store.md) -- Sealed secret management via PlatformStore
- [Server Registry](architecture/server-registry.md) -- Registered server tracking with CA fingerprint resolution
- [Token Store](architecture/token-store.md) -- Unified JWT token storage (OIDC, FIDO2, bootstrap)
- [xHome](architecture/xhome.md) -- xKey home directory layout and data paths

### [Configuration](configuration/)
- [Overview](configuration/README.md) -- All configuration options
- [Auto-Unseal](configuration/auto-unseal.md) -- Moved to [seal/](seal/)
- [Enterprise Setup](configuration/enterprise-setup.md) -- Enterprise deployment and policy configuration

### [GUI](gui/)
- [Architecture](gui/architecture.md) -- the Wails v2 app, the `App` composition root, the Wails-bound service surface, and the Unix-socket IPC server
- [Engineering](gui/engineering.md) -- exported surface, the ~44-service inventory, invariants, errors
- [CLI](gui/cli.md) -- the GUI/CLI dispatch in the `xkey` binary
- [API](gui/api.md) -- the Wails-bound service surface, grouped by method
- [User Guide](gui/user.md) -- task-oriented usage
- Superseded background, unconverted: [Overview](gui/README.md), [Features](gui/features.md), [Design System](gui/design-system.md), [Setup Wizard](gui/setup-wizard.md), [API Explorer](gui/api-explorer.md), [Browser Settings](gui/browser-settings.md), [Roadmap](gui/ROADMAP.md)

### [SSH](ssh/)
- [Architecture](ssh/architecture.md) -- the shared store, transport selection, and key-source resolution
- [Engineering](ssh/engineering.md) -- exported surface, invariants, errors
- [CLI](ssh/cli.md) -- every `xkey ssh` verb and flag
- [API](ssh/api.md) -- GUI bindings and the shared local-discovery package
- [User Guide](ssh/user.md) -- task-oriented usage

### [OATH](oath/)
- [Architecture](oath/architecture.md) -- credential model, stores, QR scanning
- [Engineering](oath/engineering.md) -- exported surface, invariants, errors, tests
- [CLI](oath/cli.md) -- `xkey oath` verbs
- [API](oath/api.md) -- GUI/SDK surface (no network transport)
- [User Guide](oath/user.md) -- add, generate, list, migrate credentials

### [OIDC](oidc/)
- [Overview](oidc/README.md) -- OpenID Connect authentication flows

### [Password](password/)
- [Architecture](password/architecture.md) -- store hierarchy, access modes, xkmsd session split
- [Engineering](password/engineering.md) -- exported surface, invariants, errors, tests
- [CLI](password/cli.md) -- `xkey password`/`xkey touch` verbs
- [API](password/api.md) -- local IPC and the xkmsd session transport
- [User Guide](password/user.md) -- store, retrieve, type, and manage sessions

### [PIV](piv/)
- [Overview](piv/README.md) -- Smart card certificate management

### [LUKS](luks/)
- [Overview](luks/README.md) -- LUKS2 encrypted storage management

### [USB](usb/)
- [CCID](usb/ccid.md) -- USB CCID smart card interface
- [Disk Images](usb/images.md) -- Portable USB disk image creation

### [PKCS#11](pkcs11/)
- [Architecture](pkcs11/architecture.md) -- why there are two transports and a separate GUI manager
- [Engineering](pkcs11/engineering.md) -- exported surface, invariants, errors
- [CLI](pkcs11/cli.md) -- `--backend pkcs11` / `--pkcs11-*` flags, by command
- [API](pkcs11/api.md) -- GUI bindings and the IPC wire protocol
- [User Guide](pkcs11/user.md) -- task-oriented usage

### [Device](device/)
- [Overview](device/README.md) -- Device management and pairing
- [Pairing](device/pairing.md) -- Device pairing flows
- [QR Pairing](device/qr-pairing.md) -- QR code pairing protocol
- [TCP Relay](device/tcp-relay.md) -- TCP relay for remote devices

### [Agent](agent/)
- [Architecture](agent/architecture.md) -- connection-time revocation and enrollment checks
- [Engineering](agent/engineering.md) -- exported surface, invariants, errors
- [CLI](agent/cli.md) -- `xkey agent` verbs
- [API](agent/api.md) -- service-layer surface reused by GUI and CLI
- [User Guide](agent/user.md) -- enrollment and removal walkthroughs

### [BLE](ble/)
- [Overview](ble/README.md) -- Bluetooth Low Energy transport
- [Architecture](ble/architecture.md) -- BLE GATT and security model
- [Protocol](ble/protocol.md) -- BLE protocol specification
- [Android App](ble/android-app.md) -- Building and using the Android app
- [Testing](ble/testing.md) -- BLE integration testing guide

### [Phone](phone/)
- [Architecture](phone/architecture.md) -- `xkey/pkg/phone`'s FIDO2 key backend, its transports, fingerprint continuity, the bidirectional xkmsd bridge, and the GUI's `PhoneService`; pairing, the Noise session, and the `device` CLI group are [phone-hsm/](phone-hsm/)
- [Engineering](phone/engineering.md) -- exported surface, invariants, errors, configuration, tests
- [CLI](phone/cli.md) -- `xkey fido2 --backend phone`
- [API](phone/api.md) -- the GUI's `PhoneService` Wails surface
- [User Guide](phone/user.md) -- task-oriented usage
- Superseded background, unconverted: [Overview](phone/README.md), [Protocol](phone/protocol.md), [Attestation](phone/attestation.md), [Bidirectional](phone/bidirectional.md), [Transport](phone/transport.md), [Backend](phone/backend/README.md), [Backend Architecture](phone/backend/architecture.md), `phone/android/`

### [Seal](seal/)
- [Architecture](seal/architecture.md) -- The Barrier, PCR-policy auto-unseal, and the legacy sealed-blob store
- [Engineering](seal/engineering.md) -- Exported surface, invariants, errors, tests
- [CLI](seal/cli.md) -- Every `xkey barrier`/`xkey policy` verb and flag
- [API](seal/api.md) -- Network-transport surface (none)
- [User Guide](seal/user.md) -- Task-oriented usage, including agent auto-unseal setup

### [Usage](usage/)
- [Overview](usage/README.md) -- CLI usage guides and tutorials
- [CLI Reference](usage/cli/README.md) -- Complete CLI command reference

### [AutoFill](autofill/)
- [Architecture](autofill/architecture.md) -- native messaging, pairing, CTAP2 verification, IPC dispatch
- [Engineering](autofill/engineering.md) -- exported surface, invariants, errors, tests
- [CLI](autofill/cli.md) -- `xkey extension` verbs
- [API](autofill/api.md) -- native messaging, IPC, and GUI-binding transports
- [User Guide](autofill/user.md) -- install, pair, fill, and configure

### [xKeySigner](xkeysigner/)
- [Overview](xkeysigner/README.md) -- crypto.Signer via IPC

### [Roadmap](roadmap/)
- [Media](roadmap/media.md) -- Media features roadmap
- [PIV](roadmap/piv.md) -- PIV features roadmap
- [Web](roadmap/web.md) -- Web features roadmap

### [Testing](testing/)
- [Phone E2E](testing/phone-e2e.md) -- Phone end-to-end test guide

## Command Structure

```
xkey
├── fido2         Start FIDO2/WebAuthn daemon
├── touch         Approve pending request or type password
├── ssh           SSH agent and key management
│   ├── agent     SSH agent operations
│   ├── keys      SSH key management
│   └── git-config  Configure git for SSH signing
├── oath          OATH TOTP/HOTP management
├── password      Static password management
├── piv           PIV certificate management
├── oidc          OIDC authentication flows
├── platform-store  Sealed secret management
├── barrier       Barrier seal/unseal management
├── luks2         LUKS2 encrypted storage management
├── config        Configuration management
└── version       Version information
```

## Global Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `~/.config/xkey/config.yaml` | Config file path |
| `--log-level` | `info` | Log level: debug, info, warn, error |
| `--log-file` | (stderr) | Log file path |

## See Also

- [go-xkms Backends](../../docs/backends/README.md) -- All supported backends
- [go-xkms Documentation](../../docs/README.md) -- Library documentation
