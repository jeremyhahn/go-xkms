# Troubleshooting

## Build Issues

### `wails` command not found

Install Wails CLI:
```bash
go install github.com/wailsapp/wails/v2/cmd/wails@latest
```

### WebKit2GTK errors on Linux

Install the development libraries:
```bash
# Debian/Ubuntu
sudo apt install libgtk-3-dev libwebkit2gtk-4.0-dev

# Fedora
sudo dnf install gtk3-devel webkit2gtk4.0-devel
```

### `CGO_ENABLED` errors during `build-gui`

GUI builds require CGO. Ensure `CGO_ENABLED=1` is set and a C compiler is available:
```bash
sudo apt install gcc
```

### Frontend build fails with module resolution errors

Clear and reinstall dependencies:
```bash
make frontend-clean
make frontend-install
make frontend-build
```

## Runtime Issues

### Desktop app shows blank window

The frontend assets may be missing from the build. The desktop app binds no port, so there is no listener to fail and no firewall rule to check: verify the SPA was built and embedded (`make frontend-build`), then check stderr for asset server errors.

### API calls fail with CORS errors in desktop mode

In desktop mode the API shares the webview's origin, so CORS should never come into play. If you see CORS errors, the frontend is calling an absolute URL instead of a relative one: check the browser console for the `__API_BASE_URL__` value, which must be empty in the desktop app.

### "Failed to get API base URL from Wails" warning

This is expected when running the SPA outside of a Wails context (e.g., via `npm run dev`). The frontend falls back to `/api/v1` relative URLs.

### Web admin UI returns 404

Ensure the server was built with the frontend embedded:
```bash
make frontend-build
make build  # or make build-gui
```

The admin SPA must be built before compiling the server binary so `go:embed` picks up the `dist/` directory.

### Theme not persisting

The theme is stored in `localStorage` under `trustedca-theme`. Clear localStorage if the value is corrupted, or check that the browser allows localStorage access.

### Connection timeout in admin desktop app

There is no admin desktop app binary in this repository (no `cactl`) — see
[`README.md`](README.md)'s correction.
