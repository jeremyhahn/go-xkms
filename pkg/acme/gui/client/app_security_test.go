// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build gui

package client

import (
	"bytes"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	svc "github.com/jeremyhahn/go-xkms/pkg/acme/client/service"
)

// indexHTML is the frontend entry point the AssetServer serves from Assets.
const indexHTML = "<!doctype html><title>trusted acme client</title>"

// testAssets stands in for the embedded Svelte bundle.
var testAssets = fstest.MapFS{
	"index.html":    &fstest.MapFile{Data: []byte(indexHTML)},
	"assets/app.js": &fstest.MapFile{Data: []byte("export const app = 1;")},
}

// newTestApp builds the application exactly as cmd/acme-client does, minus the
// window: a real service over an in-memory configuration.
func newTestApp(t *testing.T) *App {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := svc.DefaultConfig()
	service, err := svc.NewService(cfg, logger)
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	return NewApp(DefaultGUIConfig(), service, nil, logger)
}

// mountedAPI returns the handler the app hands to the Wails AssetServer, which
// is the only way the API is reachable at all.
func mountedAPI(t *testing.T, app *App) http.Handler {
	t.Helper()
	opts := app.wailsOptions(testAssets)
	if opts.AssetServer == nil {
		t.Fatal("the app must configure an AssetServer")
	}
	if opts.AssetServer.Handler == nil {
		t.Fatal("the API must be mounted as the AssetServer handler")
	}
	return opts.AssetServer.Handler
}

func request(t *testing.T, handler http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// apiRoutes is every path the desktop API exposes. OPTIONS reaches all of them
// and is answered by the router's guard, so it proves a route is mounted
// without running the handler behind it.
var apiRoutes = []string{
	"/api/v1/account/register",
	"/api/v1/accounts",
	"/api/v1/accounts/acc",
	"/api/v1/certificate/request",
	"/api/v1/certificate/renew",
	"/api/v1/certificate/revoke",
	"/api/v1/certificates",
	"/api/v1/certificates/web",
	"/api/v1/certificates/web/deploy",
	"/api/v1/device/enroll",
	"/api/v1/device/attest",
}

// =============================================================================
// The API is mounted in the asset server, alongside the frontend
// =============================================================================

// TestApp_AssetServerWiring pins the wiring the Wails AssetServer needs for
// the frontend and the API to share one origin. Per assetserver options and
// assethandler.go of wails v2.12.0, a GET is served from Assets first and
// falls back to Handler when the file does not exist, while every non-GET goes
// straight to Handler. Both must therefore be set, Assets must hold the
// index.html the asset handler insists on, and no Middleware may replace the
// chain.
func TestApp_AssetServerWiring(t *testing.T) {
	opts := newTestApp(t).wailsOptions(testAssets)
	if opts.AssetServer == nil {
		t.Fatal("the app must configure an AssetServer")
	}
	if opts.AssetServer.Assets == nil {
		t.Error("the AssetServer must keep serving the frontend assets")
	}
	if opts.AssetServer.Handler == nil {
		t.Error("the API must be mounted as the AssetServer handler")
	}
	if opts.AssetServer.Middleware != nil {
		t.Error("a middleware would replace the Assets-then-Handler chain")
	}
	if _, err := fs.Stat(opts.AssetServer.Assets, "index.html"); err != nil {
		t.Errorf("the asset handler requires an index.html: %v", err)
	}
	// A file under an "api" directory would be served from Assets and shadow
	// the API, because Assets wins for GET whenever the file exists.
	if _, err := fs.Stat(opts.AssetServer.Assets, "api"); err == nil {
		t.Error("an asset named api/ would shadow the API routes")
	}
}

func TestApp_MountedAPIServesRequests(t *testing.T) {
	handler := mountedAPI(t, newTestApp(t))

	t.Run("GET is answered by the router", func(t *testing.T) {
		rec := request(t, handler, http.MethodGet, "/api/v1/accounts", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 from the API, got %d: %s", rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("expected a JSON response, got %q", ct)
		}
	})

	t.Run("POST reaches the handler", func(t *testing.T) {
		rec := request(t, handler, http.MethodPost, "/api/v1/accounts", []byte("not json"))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected the handler's 400 for a bad body, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("the webview needs no credential", func(t *testing.T) {
		rec := request(t, handler, http.MethodGet, "/api/v1/accounts", nil)
		if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
			t.Fatalf("an in-process request must not be challenged, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("unknown path is not found", func(t *testing.T) {
		rec := request(t, handler, http.MethodGet, "/api/v1/nonexistent", nil)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for an unknown route, got %d", rec.Code)
		}
	})
}

func TestApp_MountedAPIServesEveryRoute(t *testing.T) {
	handler := mountedAPI(t, newTestApp(t))
	for _, path := range apiRoutes {
		t.Run(path, func(t *testing.T) {
			rec := request(t, handler, http.MethodOptions, path, nil)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("expected 204 from the mounted router, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestApp_MountedAPIAcceptsWebviewOrigin covers the origin a webview presents,
// which varies by platform and may be opaque. The application's own user
// interface must never be rejected by its own API.
func TestApp_MountedAPIAcceptsWebviewOrigin(t *testing.T) {
	handler := mountedAPI(t, newTestApp(t))
	for _, origin := range []string{"wails://wails", "http://wails.localhost", "null"} {
		t.Run(origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil)
			req.Header.Set("Origin", origin)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200 for Origin %q, got %d: %s", origin, rec.Code, rec.Body.String())
			}
		})
	}
}

// =============================================================================
// No network surface
// =============================================================================

// TestApp_OpensNoListeningSocket is the whole point of the design: build the
// application the way the binary does, drive its API, and prove the process
// owns no listening TCP socket afterwards.
func TestApp_OpensNoListeningSocket(t *testing.T) {
	handler := mountedAPI(t, newTestApp(t))
	if rec := request(t, handler, http.MethodGet, "/api/v1/accounts", nil); rec.Code != http.StatusOK {
		t.Fatalf("expected the API to answer, got %d", rec.Code)
	}

	if sockets := listeningSockets(t); len(sockets) != 0 {
		t.Fatalf("the desktop application must open no listener, found %v", sockets)
	}
}

// TestApp_HoldsNoListenerOrServer catches a listener being reintroduced as a
// field even where this process cannot observe /proc.
func TestApp_HoldsNoListenerOrServer(t *testing.T) {
	appType := reflect.TypeOf((*App)(nil)).Elem()
	listenerType := reflect.TypeOf((*net.Listener)(nil)).Elem()
	serverType := reflect.TypeOf(http.Server{})

	for i := 0; i < appType.NumField(); i++ {
		field := appType.Field(i)
		typ := field.Type
		if typ.Kind() == reflect.Ptr {
			typ = typ.Elem()
		}
		if field.Type.Implements(listenerType) || typ == serverType {
			t.Errorf("field %s (%s) is a network listener; the desktop app must have none", field.Name, field.Type)
		}
	}
}

// =============================================================================
// Frontend contract
// =============================================================================

// TestApp_GetApiBaseUrl_IsSameOriginRelative proves the binding hands the
// frontend a relative base: no host, no port and no credential, so the Svelte
// transport fetches "/api/v1/..." against the window's own origin.
func TestApp_GetApiBaseUrl_IsSameOriginRelative(t *testing.T) {
	if base := newTestApp(t).GetApiBaseUrl(); base != "" {
		t.Fatalf("expected an empty, same-origin base, got %q", base)
	}
}

// listeningSockets returns the local addresses of every TCP socket this
// process holds in the LISTEN state, read from /proc so it reports what the
// kernel knows rather than what the application believes. A platform without
// /proc yields nothing, which is why TestApp_HoldsNoListenerOrServer exists
// alongside it.
func listeningSockets(t *testing.T) []string {
	t.Helper()

	inodes := make(map[string]struct{})
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil
	}
	for _, fd := range fds {
		link, err := os.Readlink("/proc/self/fd/" + fd.Name())
		if err != nil {
			// The descriptor ReadDir itself used may already be closed.
			continue
		}
		if inode, ok := strings.CutPrefix(link, "socket:["); ok {
			inodes[strings.TrimSuffix(inode, "]")] = struct{}{}
		}
	}

	var listening []string
	for _, table := range []string{"/proc/self/net/tcp", "/proc/self/net/tcp6"} {
		data, err := os.ReadFile(table)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			// local_address is field 1, connection state field 3 (0A is
			// TCP_LISTEN) and the socket inode field 9.
			if len(fields) < 10 || fields[3] != "0A" {
				continue
			}
			if _, ok := inodes[fields[9]]; ok {
				listening = append(listening, fields[1])
			}
		}
	}
	return listening
}
