# Building

> **Correction (go-xkms#942):** there is no `cactl` or `trusted-acme-server`
> binary, and the root Makefile has no `build-gui`/`frontend-build-admin`/
> `build-gui-cactl` targets today. This page's Makefile and npm-workspace
> layout (`web/packages/{admin,client,shared}`) describes
> `pkg/acme/gui/{admin,client,guard,webui}`, which has no confirmed `cmd/`
> caller — see [`README.md`](README.md)'s correction. The frontend source
> for the admin UI that **is** wired (`xkmsd`'s `/admin-ui`) instead lives
> at `pkg/acme/web/packages/{admin,client,shared}`. Reconciling this page
> with that is unresolved; treat the targets and paths below as
> unverified.

## Frontend Targets

| Target | Description |
|--------|-------------|
| `make frontend-install` | Install npm dependencies (runs automatically as prerequisite) |
| `make frontend-build` | Build both admin and client frontends |
| `make frontend-build-admin` | Build admin frontend only |
| `make frontend-build-client` | Build client frontend only |
| `make frontend-clean` | Remove `node_modules` and `dist/` from all packages |
| `make frontend-dev-admin` | Start Vite dev server for admin (HMR enabled) |
| `make frontend-dev-client` | Start Vite dev server for client (HMR enabled) |

## Binary Targets

### CLI-Only (no CGO required)

```bash
make build
```

`make build` produces `bin/xkmsd` and `bin/xkmsctl` (`build-servers`,
`build-cli`, `Makefile:462-484`); there is no Makefile target that builds
`cmd/acme-client` (`trusted-acme-client`) today. See the correction above
for what this page originally claimed.

The `frontend-build` target runs first to embed the admin SPA into the server binary for web mode.

### GUI-Enabled (requires CGO + WebKit2GTK)

There is no `make build-gui`/`build-gui-server`/`build-gui-client` target
in the root Makefile. `cmd/acme-client/gui.go` builds under `-tags gui`
directly (`go build -tags gui ./cmd/acme-client`), but has no Makefile
target of its own — see the correction above.

## Build Pipeline

```
frontend-install
      |
      v
frontend-build (admin + client)
      |
      +---> make build      (CLI: embeds admin SPA for web mode)
      |
      +---> make build-gui  (Desktop: embeds both SPAs, links WebKit2GTK)
```

## npm Workspace Structure

The `web/` directory uses npm workspaces:

```
web/
  package.json          # Workspace root
  packages/
    shared/             # @trustedca/shared - components, stores, API client
    admin/              # Admin SPA (Vite + Svelte)
    client/             # Client SPA (Vite + Svelte)
```

npm scripts in the root `package.json`:

| Script | Effect |
|--------|--------|
| `npm run build` | Build admin then client |
| `npm run dev:admin` | Start admin dev server |
| `npm run dev:client` | Start client dev server |
| `npm run check` | Type-check both apps |

## Docker

GUI builds are not included in Docker images (no WebKit2GTK in containers). Docker images build CLI-only binaries with the web admin UI embedded in the server binary.
