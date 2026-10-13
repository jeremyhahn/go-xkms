# Troubleshooting

> **Status: REFERENCE** · Last verified: 2026-10-12
> Legacy, unabsorbed troubleshooting notes for the ACME SPAs and the `trusted-acme-client` desktop GUI.

## Build issues

### `ErrGUINotAvailable` when launching `trusted-acme-client`

The binary was built without the `gui` tag (`cmd/acme-client/gui_nogui.go`).
Rebuild it with `go build -tags gui ./cmd/acme-client`.

### WebKit2GTK or GTK errors on Linux

Install the development libraries:
```bash
# Debian/Ubuntu
sudo apt install libgtk-3-dev libwebkit2gtk-4.0-dev

# Fedora
sudo dnf install gtk3-devel webkit2gtk4.0-devel
```
If only WebKit2GTK 4.1 is available, add Wails' `webkit2_41` tag: `-tags gui,webkit2_41`.

### cgo errors with `-tags gui`

Wails needs cgo. Set `CGO_ENABLED=1` and make sure a C compiler is installed:
```bash
sudo apt install gcc
```

### Frontend build fails with module resolution errors

Reinstall the workspace and rebuild:
```bash
cd pkg/acme/web
rm -rf node_modules packages/*/node_modules
npm ci
npm run build
```

## Runtime issues

### Desktop app shows a blank window

The app binds no port, so this is not a listener or firewall problem. Check
that `pkg/acme/web/packages/client/dist` holds a built bundle, rebuild with
`npm run build:client` if not, then rebuild the binary so `go:embed` picks it
up. Check stderr for asset server errors.

### API calls fail with CORS errors

In the desktop app the API shares the webview's origin, so CORS should never
come into play. A CORS error means the frontend is calling an absolute URL.
Check `window.__API_BASE_URL__`, which must be empty. For a browser-hosted
router, the `pkg/acme/gui/guard` middleware rejects any `Origin` whose host
differs from the request `Host`.

### "Failed to get API base URL from Wails, using default" warning

This is expected outside Wails, for example under `npm run dev:*`. The
frontend then uses the same-origin `''` base, and the Vite proxy forwards
`/api`.

### xkmsd admin UI returns 404

The admin SPA is at `/admin-ui`, not `/ui/admin/`. xkmsd embeds
`pkg/acme/web/packages/admin/dist`. After editing the SPA, run
`npm run build:admin` and rebuild xkmsd (`make build-servers`).

### Theme toggle has no visible effect

The toggle is a known gap: Tailwind 4 `dark:` styles follow the OS setting,
not the toggle. See [theming.md](theming.md). The stored mode lives in
`localStorage` under `trustedca-theme`.
