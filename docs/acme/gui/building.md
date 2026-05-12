# Building

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

Produces three binaries without GUI support:
- `bin/trusted-acme-server`
- `bin/trusted-acme-client`
- `bin/cactl`

The `frontend-build` target runs first to embed the admin SPA into the server binary for web mode.

### GUI-Enabled (requires CGO + WebKit2GTK)

```bash
make build-gui
```

Compiles with `-tags=gui` and produces binaries with native desktop window support:

| Target | Binary | Build Tags |
|--------|--------|------------|
| `build-gui-server` | `bin/trusted-acme-server` | `gui` + project tags |
| `build-gui-client` | `bin/trusted-acme-client` | `gui` + project tags |
| `build-gui-cactl` | `bin/cactl` | `gui,iam,grpc,codec_json,codec_msgpack,codec_cbor,codec_yaml` |

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
