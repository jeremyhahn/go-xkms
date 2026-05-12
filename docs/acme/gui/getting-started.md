# Getting Started

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Go | 1.22+ | |
| Node.js | 20+ | |
| npm | 10+ | Included with Node.js |
| Wails CLI | v2 | Desktop builds only: `go install github.com/wailsapp/wails/v2/cmd/wails@latest` |
| CGO | enabled | Desktop builds only |

### Linux Dependencies

Desktop builds require WebKit2GTK:

```bash
# Debian/Ubuntu
sudo apt install libgtk-3-dev libwebkit2gtk-4.0-dev

# Fedora
sudo dnf install gtk3-devel webkit2gtk4.0-devel

# Arch
sudo pacman -S webkit2gtk
```

## Setup

```bash
# Install frontend dependencies
make frontend-install

# Build frontend bundles (admin + client)
make frontend-build
```

## Running in Dev Mode

Frontend dev servers provide hot module replacement (HMR) for rapid iteration.

```bash
# Terminal 1: Start the admin frontend dev server
make frontend-dev-admin

# Terminal 2: Start the client frontend dev server
make frontend-dev-client
```

The Vite dev servers proxy API requests to the backend. Update `vite.config.ts` proxy settings to point to your running server or embedded API.

## Building for Production

```bash
# CLI-only binaries (no native GUI, no CGO)
make build

# GUI-enabled binaries (requires CGO + WebKit2GTK)
make build-gui
```

## Running

```bash
# Launch admin desktop GUI (no subcommand = GUI mode)
./bin/cactl

# Launch client desktop GUI
./bin/trusted-acme-client

# Start ACME server with web admin UI at /ui/admin/
./bin/trusted-acme-server
```

The admin desktop GUI defaults to connecting via Unix socket at `/run/trusted-ca-grpc.sock`. Use `--transport` and `--address` flags to connect via other protocols.
