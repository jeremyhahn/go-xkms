# Getting Started

> **Status: REFERENCE** · Last verified: 2026-10-12
> Legacy, unabsorbed notes on setting up and running the ACME SPAs and the `trusted-acme-client` desktop GUI.

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Go | as in `go.mod` (1.27.4) | |
| Node.js + npm | 20+ | Only to rebuild the SPAs. Vite 6 needs a current Node LTS |
| Wails CLI | v2 | Optional: `wails dev` / `wails build` from `cmd/acme-client` |
| cgo | enabled | Desktop (`-tags gui`) builds only |

### Linux dependencies

Desktop builds link GTK 3 and WebKit2GTK through Wails v2:

```bash
# Debian/Ubuntu
sudo apt install build-essential libgtk-3-dev libwebkit2gtk-4.0-dev

# Fedora
sudo dnf install gtk3-devel webkit2gtk4.0-devel
```

Distributions that ship only WebKit2GTK 4.1 need Wails v2's `webkit2_41` build
tag as well: `-tags gui,webkit2_41`.

## Setup

```bash
cd pkg/acme/web
npm ci
npm run build      # optional: dist/ is committed
```

## Dev mode

The Vite dev servers give hot module replacement:

```bash
cd pkg/acme/web
npm run dev:admin    # http://localhost:5173, /api proxied to https://localhost:8443
npm run dev:client   # http://localhost:5174, /api proxied to http://localhost:18443
```

Edit the `server.proxy` block of each package's `vite.config.ts` to point at
your backend.

## Building and running

```bash
# Desktop client GUI
go build -tags gui -o bin/trusted-acme-client ./cmd/acme-client
./bin/trusted-acme-client          # no subcommand opens the window

# xkmsd, which serves the admin SPA at /admin-ui
make build-servers
```

There is no admin desktop binary: `pkg/acme/gui/admin` has no `cmd/` caller.
See [README.md](README.md).
