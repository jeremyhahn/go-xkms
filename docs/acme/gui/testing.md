# Testing

## Unit Tests

Frontend unit tests validate component behavior and store logic. Run via:

```bash
cd web && npm run check
```

Type checking covers both admin and client packages.

## API Testing

The embedded REST APIs are standard HTTP servers testable with any HTTP client:

```bash
# Example: test admin status endpoint against running desktop app
curl http://localhost:{port}/api/v1/status
```

For automated testing, use Go's `httptest` package against the router:

```go
router := adminapi.NewRouter(factory, logger)
req := httptest.NewRequest("GET", "/api/v1/status", nil)
w := httptest.NewRecorder()
router.ServeHTTP(w, req)
```

## Integration Tests

Integration tests exercise the full stack via the `platformctl` CLI across all protocols. See the project-level testing conventions in `CLAUDE.md` for the multi-protocol test pattern.

GUI integration tests are in `test/integration/gui/` and run inside the devcontainer with real server resources.

## Build Verification

```bash
# Verify frontend builds without errors
make frontend-build

# Verify GUI binaries compile
make build-gui

# Type check frontend code
cd web && npm run check
```
