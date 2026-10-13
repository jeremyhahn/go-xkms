# Building

> **Status: REFERENCE** · Last verified: 2026-10-12
> Legacy, unabsorbed notes on building the ACME SPAs (`pkg/acme/web`) and the `trusted-acme-client` desktop GUI.

No Makefile target builds `pkg/acme/web` or `cmd/acme-client`. The Makefile's
`build-web`, `dev-web`, `test-web` and `build-desktop` targets build the
separate `web/app` frontend, not these SPAs.

## Frontend

The `dist/` output of each package is committed and embedded by Go, so a
rebuild is needed only after editing the Svelte sources.

```bash
cd pkg/acme/web
npm ci                  # install the workspace from package-lock.json
npm run build           # admin, then client
```

Scripts in `pkg/acme/web/package.json`:

| Script | Effect |
|--------|--------|
| `npm run build` | Build admin, then client |
| `npm run build:admin` / `build:client` | Build one app |
| `npm run dev:admin` / `dev:client` | Vite dev server with HMR |
| `npm run preview:admin` / `preview:client` | Serve the built bundle |
| `npm run check` | `svelte-check` both apps |

## Go binaries

```bash
# CLI only, no cgo or WebKit needed
go build -o bin/trusted-acme-client ./cmd/acme-client

# With the desktop GUI (cgo, Wails v2, WebKit2GTK)
go build -tags gui -o bin/trusted-acme-client ./cmd/acme-client

# xkmsd embeds the admin SPA for /admin-ui
make build-servers
```

`cmd/acme-client/wails.json` is also present, so `wails build` works from
`cmd/acme-client`. Its frontend build command is `npm run build:client` in
`pkg/acme/web`.

## Pipeline

```
pkg/acme/web (npm run build)
      |
      +--> packages/admin/dist  --embed--> xkmsd (/admin-ui), pkg/acme/gui/webui.AdminAssets
      +--> packages/client/dist --embed--> pkg/acme/gui/webui.ClientAssets --> trusted-acme-client -tags gui
```

## npm workspace

```
pkg/acme/web/
  package.json          # workspace root
  package-lock.json
  packages/
    shared/             # @trustedca/shared: components, stores, API client
    admin/              # @trustedca/admin: admin SPA (Vite + Svelte 5)
    client/             # @trustedca/client: client SPA (Vite + Svelte 5)
```
