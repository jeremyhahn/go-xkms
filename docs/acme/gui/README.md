# GUI System

> **The admin UI xkmsd actually serves is `/admin-ui`**, a separate
> implementation (`pkg/acme/web/packages/admin`) mounted by
> `cmd/xkmsd/admin.go:73` / `finalizeAdminModule`
> (`cmd/xkmsd/admin.go:130`) — see [REST Protocol](../protocols/rest.md).
>
> **Correction (go-xkms#942):** this page describes `pkg/acme/gui/{admin,client,guard,webui}`
> and a `cactl` binary. There is no `cactl` in this repository, and
> `pkg/acme/gui/admin`/`pkg/acme/api/server` (which would mount its web
> build at `/ui/admin/`) have no current `cmd/` entry point — grepping
> the tree turns up no caller of `server.NewMultiProtocolServer`
> (`pkg/acme/api/server/server.go:164`) outside its own package. Per the
> go-xkms#696 ruling, this is a half-built feature to be wired, not
> deleted: `pkg/acme/gui/admin` is the **desktop host** (Wails) for the
> same admin SPA `/admin-ui` also serves in web mode, and which binary
> hosts it is tracked in go-xkms#743 / go-xkms#746. Until one exists, only
> the *client* GUI below (`trusted-acme-client`, `cmd/acme-client/gui.go`)
> is confirmed wired.

go-xkms provides a dual-mode GUI for both the ACME client and the CA admin interface. A single Svelte 4 frontend bundle runs identically in two environments:

- **Desktop mode** -- Wails v2 wraps the SPA in a native webview and serves the REST API from the same in-process asset server, opening no network listener
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
| `trusted-acme-client` (`cmd/acme-client`) | cobra subcommands | no subcommand = GUI (`-tags gui`) | -- |
| `xkmsd` | yes | -- | hosts the (separately implemented) admin web UI at `/admin-ui` |

There is no `cactl` binary and no `trusted-acme-server` binary in this
repository.

## Quick Start

```bash
# 1. Install frontend dependencies and build
make frontend-build

# 2. Build CLI-only binaries (no CGO required)
make build

# 3. Build GUI-enabled binaries (requires CGO + Wails + WebKit2GTK)
make build-gui

# 4. Launch the desktop client GUI
./bin/trusted-acme-client
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
