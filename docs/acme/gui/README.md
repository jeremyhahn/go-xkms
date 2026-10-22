# GUI System

> **Status: REFERENCE** · Last verified: 2026-10-12
> Legacy, unabsorbed notes on the ACME admin and client Svelte SPAs and their Wails desktop hosts.

The ACME stack ships two Svelte 5 single-page apps, built from the npm
workspace at `pkg/acme/web/packages/{admin,client,shared}`:

- **Admin SPA** (`pkg/acme/web/packages/admin`). `xkmsd` serves it at
  `/admin-ui`: `newAdminModule` takes its embedded `dist/`
  (`cmd/xkmsd/admin.go:92`) and mounts it with `WithAdminWebUI`
  (`cmd/xkmsd/admin.go:104`, prefix constant at `:55`). See
  [acme-issuance/user.md](../../acme-issuance/user.md#browsing-the-api-interactively).
- **Client SPA** (`pkg/acme/web/packages/client`). The `trusted-acme-client`
  desktop GUI (`cmd/acme-client/gui.go`, built with `-tags gui`) hosts it.

- **Admin desktop** (`pkg/acme/gui/admin`). `xkmsctl acme gui`, built with
  `-tags gui` (`make build-cli-gui`), hosts it (`cmd/xkmsctl/acme_gui.go:99`).
  See [acme-issuance/cli.md](../../acme-issuance/cli.md#xkmsctl-acme-gui).

One host for the admin SPA exists in code but no binary uses it:

- `pkg/acme/api/server` mounts the SPA at `/ui/admin/` through
  `webui.RegisterRoutes` (`pkg/acme/api/server/server.go:670`). Nothing outside
  that package calls `server.NewMultiProtocolServer`
  (`pkg/acme/api/server/server.go:165`).

```
        Desktop (Wails, -tags gui)                    Web (xkmsd)
   +-----------------------------------+      +--------------------------+
   | native webview                    |      | browser tab              |
   |  Svelte SPA --fetch('/api/v1/..') |      |  admin SPA at /admin-ui  |
   |        |  same origin, no socket  |      |        | fetch()         |
   |  Wails AssetServer                |      |        v                 |
   |   Assets: embedded dist/          |      | xkmsd admin module       |
   |   Handler: gorilla/mux /api/v1    |      |  /admin/*, /api/v1/...   |
   +-----------------------------------+      +--------------------------+
```

## Binaries

| Binary | CLI | Desktop GUI | Web GUI |
|--------|-----|-------------|---------|
| `trusted-acme-client` (`cmd/acme-client`) | cobra subcommands | running with no subcommand when a display is present (`-tags gui`) | -- |
| `xkmsd` | -- | -- | admin SPA at `/admin-ui` |

## Quick Start

No Makefile target builds these SPAs or `trusted-acme-client`. The `dist/`
bundles are committed, so a Go build embeds them as they are:

```bash
# Rebuild the SPAs (optional; dist/ is committed)
cd pkg/acme/web && npm ci && npm run build && cd -

# Build and launch the desktop client (needs cgo, Wails v2 and WebKit2GTK)
go build -tags gui -o bin/trusted-acme-client ./cmd/acme-client
./bin/trusted-acme-client
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Desktop and web hosting, transport detection, build tags |
| [Getting Started](getting-started.md) | Prerequisites, setup, first run |
| [Building](building.md) | npm workspace, Go build commands |
| [Client GUI](client/) | ACME client desktop application |
| [Admin GUI](admin/) | CA admin SPA and its hosts |
| [Frontend Development](frontend-development.md) | Workspace, components, stores, adding views |
| [Component Library](component-library.md) | Shared Svelte components reference |
| [Theming](theming.md) | Dark/light mode, Tailwind configuration |
| [Testing](testing.md) | Testing strategy |
| [Troubleshooting](troubleshooting.md) | Common issues and fixes |
