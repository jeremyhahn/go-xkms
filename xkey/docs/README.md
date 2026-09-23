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
| [headless-webauthn](headless-webauthn/) | Programmatic WebAuthn ceremonies without a browser or a human | `fido2/` (with `virtual-authenticator`) |
| [oidc](oidc/) | OpenID Connect relying-party login and the CLI's barrier-backed session token store | `oidc/` |
| [phone-hsm](phone-hsm/) | The phone-as-HSM backend and its pairing protocol | `phone/` |
| [platform-trust](platform-trust/) | Trust bootstrap, the classified truststore, platform CA import | `architecture/server-registry.md` (trust half) |
| [setup-wizard](setup-wizard/) | First-run setup: quick and manual personal setup, enterprise SO provisioning and onboarding, and where the generated SO PIN may live | `gui/setup-wizard.md`, `seal/setup-wizard.md` |
| [share-custody](share-custody/) | The Shamir share custody client | — |
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

Still owed a folder: `autofill/`, `ble/`, `device/`, `fido2/`, `gui/`, `luks/`, `oath/`,
`password/`, `phone/`, `piv/`, `pkcs11/`, `seal/`, `ssh/`, `usb/`,
`xkeysigner/`. Not features and staying as they are: `architecture/`,
`configuration/`, `roadmap/`, `testing/`, `usage/`.

## Documentation Structure

| Directory | Description |
|-----------|-------------|
| [agent/](agent/) | Agent enrollment and management |
| [architecture/](architecture/) | System architecture, internal design, and data stores |
| [ble/](ble/) | Bluetooth Low Energy transport and Android pairing |
| [configuration/](configuration/) | Application configuration, auto-unseal, and enterprise setup |
| [device/](device/) | Device pairing, QR pairing, and TCP relay |
| [fido2/](fido2/) | FIDO2/WebAuthn daemon and CTAP2 authenticator library |
| [gui/](gui/) | Desktop GUI application, design system, and setup wizard |
| [luks/](luks/) | LUKS2 encrypted storage management |
| [oath/](oath/) | OATH TOTP/HOTP credential management with QR scanning |
| [oidc/](oidc/) | OpenID Connect authentication flows and provider management |
| [password/](password/) | Static password management with encryption and access modes |
| [phone/](phone/) | Phone backend, bidirectional key sharing, and attestation |
| [piv/](piv/) | PIV smart card certificate management |
| [pkcs11/](pkcs11/) | PKCS#11 IPC transport for Unix socket crypto operations |
| [roadmap/](roadmap/) | Feature roadmaps for media, PIV, and web |
| [seal/](seal/) | TPM sealing, auto-unseal, platform policy, and setup wizard seal integration |
| [ssh/](ssh/) | SSH agent with standalone and server modes |
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
- [Overview](fido2/README.md) -- FIDO2 daemon with all backend options
- [Daemon Overview](fido2/overview.md) -- what `xkey fido2` is and what it owns
- [Daemon Architecture](fido2/daemon-architecture.md) -- UHID device, IPC socket, keyboard, CDP bridge
- [Daemon Configuration](fido2/daemon-configuration.md) -- flags, environment variables, config file
- [Authenticator Overview](fido2/authenticator-overview.md) -- CTAP2 virtual authenticator implementation
- [Authenticator API](fido2/authenticator-api.md) -- Complete API documentation
- [Authenticator Architecture](fido2/authenticator-architecture.md) -- Component design and data flows
- [Authenticator Configuration](fido2/authenticator-config.md) -- Library configuration reference
- [Authenticator Security](fido2/authenticator-security.md) -- Security model and threat analysis
- [Authenticator Examples](fido2/authenticator-examples.md) -- Usage examples and code samples

### [Architecture](architecture/)
- [Overview](architecture/README.md) -- System architecture and component design
- [Platform Store](architecture/platform-store.md) -- Sealed secret management via PlatformStore
- [Server Registry](architecture/server-registry.md) -- Registered server tracking with CA fingerprint resolution
- [Token Store](architecture/token-store.md) -- Unified JWT token storage (OIDC, FIDO2, bootstrap)
- [xHome](architecture/xhome.md) -- xKey home directory layout and data paths

### [Configuration](configuration/)
- [Overview](configuration/README.md) -- All configuration options
- [Auto-Unseal](configuration/auto-unseal.md) -- Automated unlock via PlatformStore and barrier
- [Enterprise Setup](configuration/enterprise-setup.md) -- Enterprise deployment and policy configuration

### [GUI](gui/)
- [Overview](gui/README.md) -- Desktop GUI application
- [Architecture](gui/architecture.md) -- GUI component design
- [Features](gui/features.md) -- Feature documentation
- [Design System](gui/design-system.md) -- Design system reference
- [Setup Wizard](gui/setup-wizard.md) -- First-run setup wizard
- [API Explorer](gui/api-explorer.md) -- Authenticated HTTP client with auto JWT injection
- [Browser Settings](gui/browser-settings.md) -- Platform-aware browser launcher configuration
- [Roadmap](gui/ROADMAP.md) -- Planned GUI features

### [SSH](ssh/)
- [Overview](ssh/README.md) -- SSH agent with standalone and server modes

### [OATH](oath/)
- [Overview](oath/README.md) -- TOTP/HOTP with QR scanning

### [OIDC](oidc/)
- [Overview](oidc/README.md) -- OpenID Connect authentication flows

### [Password](password/)
- [Overview](password/README.md) -- Static password management with encryption and access modes

### [PIV](piv/)
- [Overview](piv/README.md) -- Smart card certificate management

### [LUKS](luks/)
- [Overview](luks/README.md) -- LUKS2 encrypted storage management

### [USB](usb/)
- [CCID](usb/ccid.md) -- USB CCID smart card interface
- [Disk Images](usb/images.md) -- Portable USB disk image creation

### [PKCS#11](pkcs11/)
- [IPC Transport](pkcs11/ipc.md) -- Unix socket transport for PKCS#11 module and crypto.Signer

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
- [Overview](phone/README.md) -- Phone backend and key sharing
- [Protocol](phone/protocol.md) -- Bidirectional JSON-RPC 2.0 protocol
- [Attestation](phone/attestation.md) -- Bidirectional attestation flows
- [Bidirectional](phone/bidirectional.md) -- Bidirectional key sharing design
- [Transport](phone/transport.md) -- BLE and USB transport layers
- [Backend](phone/backend/README.md) -- Phone-as-a-token integration
- [Backend Architecture](phone/backend/architecture.md) -- Phone backend internals

### [Seal](seal/)
- [Overview](seal/README.md) -- TPM sealing and auto-unseal
- [Setup Wizard](seal/setup-wizard.md) -- Seal integration in setup wizard
- [Platform Policy](seal/platform-policy.md) -- PCR-based platform policy

### [Usage](usage/)
- [Overview](usage/README.md) -- CLI usage guides and tutorials
- [CLI Reference](usage/cli/README.md) -- Complete CLI command reference

### [AutoFill](autofill/)
- [Overview](autofill/README.md) -- Browser extension architecture
- [Extension](autofill/extension.md) -- Extension implementation
- [Policy](autofill/policy.md) -- AutoFill policy management

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
