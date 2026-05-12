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

The embedded HTTP server may have failed to start. Check stderr for port binding errors. Ensure no firewall is blocking loopback connections.

### API calls fail with CORS errors in desktop mode

The embedded server includes CORS middleware allowing all origins. If you see CORS errors, verify the transport layer initialized correctly by checking the browser console for the `__API_BASE_URL__` value.

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

The default transport is Unix socket at `/run/trusted-ca-grpc.sock`. Verify the CA server is running and the socket file exists:
```bash
ls -la /run/trusted-ca-grpc.sock
```

To connect via a different protocol, use the Connection Settings view or CLI flags:
```bash
./bin/cactl --transport rest --address localhost:8443
```
