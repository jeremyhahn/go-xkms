# xKey Desktop GUI

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

All 10 implementation phases (0-9) are complete.

| Metric | Value |
|--------|-------|
| Go tests passing | 97 |
| Frontend errors | 0 (vite build + svelte-check) |
| Frontend warnings | 0 |
| CSS bundle | 80 KB (12 KB gzip) |
| JS bundle | 252 KB (68 KB gzip) |
| Frontend components | 24 |
| Frontend views | 15 |
| Frontend stores | 8 |
| Frontend utils | 3 |
| Backend services | 8 (App, Phone, FIDO2, OATH, PIV, TPM, Audit, Admin) |

## Quick Start

```bash
cd xkey

# Build both CLI and GUI binaries
make build

# Build CLI only
make build-cli          # produces ./build/bin/xkey

# Build GUI only (requires wails CLI)
make build-gui          # produces ./build/bin/xkey-gui

# Run GUI (auto-detects display server; falls back to CLI with --no-gui)
./build/bin/xkey-gui
./build/bin/xkey-gui --no-gui   # force CLI fallback

# Run CLI only (no GUI dependencies)
./build/bin/xkey

# Development mode with hot reload
make dev-gui
```

## Architecture

```
xkey/
  main.go               GUI entry point (Wails + embed + systray)
                           --no-gui flag falls back to CLI
  cmd/xkey/main.go      CLI-only entry point (cobra/viper)

┌─────────────────────────────────────────────────────────────────────┐
│                      xkey-gui Binary                                │
│  main.go: GUI Entry Point                                           │
│    ├── hasGUIEnvironment() -> detect X11 / Wayland / macOS / Win   │
│    ├── --no-gui | --help | -h -> CLI fallback (cobra/viper)        │
│    └── GUI Mode -> Wails + embed frontend/dist + systray           │
├─────────────────────────────────────────────────────────────────────┤
│                      xkey Binary (CLI-only)                         │
│  cmd/xkey/main.go: CLI Entry Point                                  │
│    └── cobra/viper command tree (no GUI dependencies)              │
├─────────────────────────────────────────────────────────────────────┤
│  Frontend (Svelte 4 + TypeScript + TailwindCSS)                     │
│    ├── 24 Components (Card, Button, Modal, Toast, PCRViewer, ...)  │
│    ├── 15 Views (Dashboard, Devices, FIDO2, OATH, PIV, TPM, ...)  │
│    ├── 8 Stores (app, theme, phone, keys, oath, fido2, events,    │
│    │             notifications)                                     │
│    └── 3 Utils (theme, format, icons)                              │
├─────────────────────────────────────────────────────────────────────┤
│  Backend (Go)                                                       │
│    ├── 8 Services: App, Phone, FIDO2, OATH, PIV, TPM, Audit,      │
│    │               Admin (Wails bindings exposed to frontend)      │
│    ├── TrayManager (fyne.io/systray integration)                   │
│    ├── Events System (bidirectional Go <-> frontend events)        │
│    └── Config Persistence (~/.xkey/gui.json, atomic writes)        │
└─────────────────────────────────────────────────────────────────────┘
```

## Build Commands

| Command | Description |
|---------|-------------|
| `make build` | Build both CLI and GUI binaries |
| `make build-cli` | CLI only (no GUI dependencies) |
| `make build-gui` | GUI only (requires wails CLI) |
| `make dev-gui` | Dev mode with hot reload |
| `make frontend-build` | Frontend only |
| `make test` | Run all unit tests with coverage |
| `make coverage-gui` | GUI test coverage report |

## Configuration

The GUI persists its own configuration as JSON at `~/.xkey/gui.json`. Writes are atomic (temp-file + rename) to prevent corruption. Viper keys from environment variables and CLI flags override the JSON file values.

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

1. **CLI flags / environment variables** (`XKEY_GUI_THEME`, etc. via viper)
2. **JSON file** (`~/.xkey/gui.json`)
3. **Defaults** (system theme, 1024x768, notifications enabled)

## Documentation

- [Architecture](./architecture.md) - Technical architecture and component design
- [Design System](./design-system.md) - Colors, typography, components matching Android
- [Features](./features.md) - Detailed feature specifications
- [ROADMAP](./ROADMAP.md) - Development checklist and milestones

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Framework | [Wails v2](https://wails.io/) | Go + Web hybrid desktop apps |
| Frontend | Svelte 4 + TypeScript | Reactive UI components |
| Styling | TailwindCSS | Utility-first CSS matching Android design |
| Systray | [fyne.io/systray](https://github.com/fyne-io/systray) | Cross-platform tray integration |
| Icons | Material Design Icons | Consistent with Android |
| State | Svelte Stores | Reactive state management |

## Comparison with YubiKey Authenticator

| Feature | YubiKey Authenticator | xKey Desktop |
|---------|----------------------|--------------|
| TOTP/HOTP | Yes | Yes |
| FIDO2/WebAuthn | Limited | Full Management |
| PIV Certificates | Yes | Yes + CSR Generation |
| Phone Backend | No | Yes (BLE + TCP) |
| TPM Integration | No | Full TPM2 Support |
| Server Admin | No | xkmsd Management |
| Audit Logging | No | Comprehensive |
| Multi-Device | No | Yes (Phone + Hardware) |
| Custom Themes | No | Light/Dark + System |

## Security Considerations

- All cryptographic operations happen in Go backend
- Frontend never has access to private keys
- IPC is secured via Wails runtime
- Biometric prompts use native OS dialogs
- Audit log tracks all security operations

## License

Copyright (c) 2025 Jeremy Hahn
Copyright (c) 2025 Automate The Things, LLC

Dual-licensed under AGPL-3.0 and Commercial License.
