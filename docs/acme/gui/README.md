# GUI System

go-xkms provides a dual-mode GUI for both the ACME client and the CA admin interface. A single Svelte 4 frontend bundle runs identically in two environments:

- **Desktop mode** -- Wails v2 wraps the SPA in a native webview with an embedded HTTP server on a random port
- **Web mode** -- The ACME server hosts the admin SPA at `/ui/admin/`, using the server's existing REST API

```
                       Desktop Mode                          Web Mode
                  +---------------------+           +------------------------+
                  |    Wails Webview     |           |     Browser Tab        |
                  |  (native window)    |           |                        |
                  |  +---------------+  |           |  +------------------+  |
                  |  | Svelte SPA    |  |           |  | Svelte SPA       |  |
                  |  | (admin or     |  |           |  | (admin)          |  |
                  |  |  client)      |  |           |  +--------+---------+  |
                  |  +-------+-------+  |           +-----------|------------+
                  +---------|----------+                        |
                            | fetch()                           | fetch()
                            v                                   v
                  +-------------------+             +------------------------+
                  | Embedded HTTP     |             | ACME Server            |
                  | 127.0.0.1:{rand}  |             | :8443/api/v1           |
                  | /api/v1           |             | /ui/admin/ (SPA files) |
                  +-------------------+             +------------------------+
```

## Binaries

| Binary | CLI | Desktop GUI | Web GUI |
|--------|-----|-------------|---------|
| `trusted-acme-client` | cobra subcommands | no subcommand = GUI | -- |
| `cactl` | cobra subcommands | no subcommand = GUI | -- |
| `trusted-acme-server` | yes | -- | hosts admin at `/ui/admin/` |

## Quick Start

```bash
# 1. Install frontend dependencies and build
make frontend-build

# 2. Build CLI-only binaries (no CGO required)
make build

# 3. Build GUI-enabled binaries (requires CGO + Wails + WebKit2GTK)
make build-gui

# 4. Launch desktop admin GUI
./bin/cactl
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Dual-mode design, transport abstraction, build tags |
| [Getting Started](getting-started.md) | Prerequisites, setup, first run |
| [Building](building.md) | Makefile targets, dev vs prod builds |
| [Client GUI](client/) | ACME client desktop application |
| [Admin GUI](admin/) | CA admin desktop and web application |
| [Frontend Development](frontend-development.md) | Workspace, components, stores, adding views |
| [Component Library](component-library.md) | Shared Svelte components reference |
| [Theming](theming.md) | Dark/light mode, TailwindCSS config |
| [Testing](testing.md) | Testing strategy |
| [Troubleshooting](troubleshooting.md) | Common issues and fixes |
