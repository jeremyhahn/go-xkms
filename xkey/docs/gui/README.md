# xKey Desktop GUI

> **Status: REFERENCE** · Last verified: 2026-10-13
> Superseded background: the GUI feature folder, starting with [architecture.md](architecture.md), is normative.

A premium cross-platform desktop application for xKey, built with [Wails](https://wails.io/) to provide a native experience that matches the xKey Android app.

## Overview

The xKey Desktop GUI provides a system tray application with full window support for managing hardware security keys, phone backends, FIDO2/WebAuthn credentials, OATH TOTP codes, PIV certificates, and TPM operations.

### Design Philosophy

- **Visual Parity**: Identical look and feel to the xKey Android app
- **Premium Experience**: Deep Navy, Warm Gold, Rich Teal color palette
- **Security-First**: All operations require appropriate authorization
- **Feature Complete**: Full CLI functionality exposed through intuitive UI
- **Cross-Platform**: Windows, macOS, and Linux support

## Current Status

All 10 implementation phases (0-9) of the original [ROADMAP](./ROADMAP.md) are
complete. The frontend views are in `xkey/frontend/src/views/`, shared
components in `xkey/frontend/src/lib/components/`, stores in
`xkey/frontend/src/lib/stores/`, and the Go services bound to the frontend in
`xkey/pkg/gui/services/`.

## Quick Start

```bash
cd xkey

# Build the single xkey binary (GUI + CLI) in the Docker builder image
make build              # produces <BIN_DIR>/xkey

# Build locally instead (needs the webkit, libusb and bluetooth dev packages)
make build-local

# Run: GUI when a display is detected, CLI otherwise
./build/bin/xkey
./build/bin/xkey --no-gui   # force the CLI

# Development mode with Wails hot reload
make dev
```

`BIN_DIR` defaults to `$(WORKSPACE_ROOT)/build/bin` (`xkey/Makefile`).

## Architecture

```
xkey/
  cmd/xkey/main.go      The one entry point: GUI or CLI
  pkg/gui/              Wails app, systray, config, events, services

┌─────────────────────────────────────────────────────────────────────┐
│                      xkey Binary                                    │
│  cmd/xkey/main.go                                                   │
│    ├── hasGUIEnvironment() -> detect a display                      │
│    ├── --no-gui | --help | -h -> CLI (cobra/viper)                  │
│    ├── --gui -> force the GUI                                       │
│    └── GUI Mode -> Wails + embedded frontend + systray              │
├─────────────────────────────────────────────────────────────────────┤
│  Frontend (Svelte 4 + TypeScript + TailwindCSS)                     │
│    ├── src/views/            (Dashboard, FIDO2, OATH, PIV, TPM, ...)│
│    ├── src/lib/components/   (Card, Button, Modal, PCRViewer, ...)  │
│    ├── src/lib/stores/       (app, theme, keys, oath, fido2, ...)   │
│    └── src/lib/utils/                                               │
├─────────────────────────────────────────────────────────────────────┤
│  Backend (Go)                                                       │
│    ├── pkg/gui/services/  (Wails bindings exposed to frontend)      │
│    ├── TrayManager (fyne.io/systray integration)                    │
│    ├── Events System (Go -> frontend events)                        │
│    └── Config Persistence (<config dir>/xkey/gui.json, atomic)      │
└─────────────────────────────────────────────────────────────────────┘
```

The GUI/CLI decision is in `xkey/cmd/xkey/main.go:65-73`;
`hasGUIEnvironment()` is at `xkey/cmd/xkey/main.go:295`.

## Build Commands

| Command | Description |
|---------|-------------|
| `make build` | Build the xkey binary (GUI + CLI) in Docker |
| `make build-local` | Build the same binary on the host |
| `make dev` | Wails dev mode with hot reload |
| `make frontend-build` | Frontend only |
| `make test` | Run all unit tests |
| `make coverage-gui` | GUI test coverage report |

## Configuration

The GUI persists its own configuration as JSON at `gui.json` in the `xkey`
directory under the OS user config dir (`os.UserConfigDir()`, e.g.
`$XDG_CONFIG_HOME/xkey/gui.json` on Linux; `configDir` and `guiConfigPath` in
`xkey/pkg/gui/config.go:263` and `:283`). Writes are atomic
(`fsutil.WriteFileAtomic`, `xkey/pkg/gui/config.go:445`). Viper keys under
`gui.` (for example `gui.theme`) override the JSON file values when set
(`LoadGUIConfig`, `xkey/pkg/gui/config.go:294`).

A subset of the fields (`GUIConfig`, `xkey/pkg/gui/config.go`):

```json
{
  "auto_tray": true,
  "theme": "system",
  "start_minimized": false,
  "notifications": true,
  "window_width": 1024,
  "window_height": 768,
  "remember_position": true,
  "window_x": 0,
  "window_y": 0
}
```

### Configuration Sources (highest to lowest precedence)

1. **Viper keys** (`gui.*`, from flags, environment or the xkey config file)
2. **JSON file** (`gui.json`)
3. **Defaults** (`DefaultGUIConfig`, `xkey/pkg/gui/config.go:196`)

## Documentation

- [Architecture](./architecture.md) - Technical architecture and component design
- [Design System](./design-system.md) - Colors, typography, components matching Android
- [Features](./features.md) - Detailed feature specifications
- [ROADMAP](./ROADMAP.md) - Development checklist and milestones (archived)

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Framework | [Wails v2](https://wails.io/) | Go + Web hybrid desktop apps |
| Frontend | Svelte 4 + TypeScript | Reactive UI components |
| Styling | TailwindCSS | Utility-first CSS matching Android design |
| Systray | [fyne.io/systray](https://github.com/fyne-io/systray) | Cross-platform tray integration |
| Icons | Material Design Icons (`@mdi/js`) | Consistent with Android |
| State | Svelte Stores | Reactive state management |

## Comparison with YubiKey Authenticator

| Feature | YubiKey Authenticator | xKey Desktop |
|---------|----------------------|--------------|
| TOTP/HOTP | Yes | Yes |
| FIDO2/WebAuthn | Limited | Full Management |
| PIV Certificates | Yes | Yes + CSR Generation |
| Phone Backend | No | Yes |
| TPM Integration | No | Full TPM2 Support |
| Server Admin | No | xkmsd Management |
| Audit Logging | No | Yes |
| Multi-Device | No | Yes (Phone + Hardware) |
| Custom Themes | No | Light/Dark + System |

## Security Considerations

- All cryptographic operations happen in Go backend
- Frontend never has access to private keys
- IPC is secured via Wails runtime
- Audit log tracks security operations

## License

Copyright (c) 2025 Jeremy Hahn
Copyright (c) 2025 Automate The Things, LLC

Dual-licensed under AGPL-3.0 and Commercial License.
