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

package admin

import (
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

	"github.com/gorilla/mux"
)

// indexHTML is the frontend entry point the AssetServer serves from Assets.
const indexHTML = "<!doctype html><title>trusted ca admin</title>"

// testAssets stands in for the embedded Svelte bundle.
var testAssets = fstest.MapFS{
	"index.html": &fstest.MapFile{Data: []byte(indexHTML)},
}

// newTestApp builds the admin application without a window. The SDK client is
// nil: every assertion here is about reachability, and a request that reached
// a handler would be a request that should never have been routable.
func newTestApp() *App {
	return NewApp(DefaultGUIConfig(), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
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

func request(t *testing.T, handler http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
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
	opts := newTestApp().wailsOptions(testAssets)
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

// routes reports whether the mounted router routes the given request to a
// handler. Matching rather than serving is deliberate: it proves reachability
// through the mounted handler without invoking an admin handler against the
// nil SDK client.
func routes(t *testing.T, router *mux.Router, method, path string) bool {
	t.Helper()
	var match mux.RouteMatch
	return router.Match(httptest.NewRequest(method, path, nil), &match) && match.Handler != nil
}

func TestApp_MountedAPIRoutesRequests(t *testing.T) {
	router, ok := mountedAPI(t, newTestApp()).(*mux.Router)
	if !ok {
		t.Fatal("the admin API handler must be the mux router")
	}

	// The privileged operations that used to answer on a loopback port with
	// no guard at all: each must still route, and now only from in-process.
	reachable := []struct{ method, path string }{
		{http.MethodGet, "/admin/status"},
		{http.MethodPost, "/api/v1/tenants/"},
		{http.MethodDelete, "/api/v1/tenants/t1"},
		{http.MethodPost, "/api/v1/tenants/t1/root-ca"},
		{http.MethodPost, "/api/v1/tenants/t1/intermediate-cas"},
		{http.MethodPost, "/api/v1/tenants/t1/users"},
		{http.MethodDelete, "/api/v1/tenants/t1/users/u1"},
		{http.MethodPost, "/api/v1/tenants/t1/roles"},
		{http.MethodPost, "/admin/certificates/abc123/revoke"},
	}
	for _, rt := range reachable {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			if !routes(t, router, rt.method, rt.path) {
				t.Fatalf("%s %s is not routed by the mounted handler", rt.method, rt.path)
			}
		})
	}

	t.Run("unknown path is not routed", func(t *testing.T) {
		if routes(t, router, http.MethodGet, "/api/v1/nonexistent") {
			t.Fatal("an unknown path must not match a route")
		}
		rec := request(t, handlerOf(router), http.MethodGet, "/api/v1/nonexistent")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for an unknown route, got %d", rec.Code)
		}
	})
}

// handlerOf returns the router as a plain http.Handler.
func handlerOf(router *mux.Router) http.Handler { return router }

// =============================================================================
// No network surface
// =============================================================================

// TestApp_OpensNoListeningSocket proves the admin application, whose API
// creates tenants, users, roles and CAs, is unreachable from off-process.
func TestApp_OpensNoListeningSocket(t *testing.T) {
	router, ok := mountedAPI(t, newTestApp()).(*mux.Router)
	if !ok {
		t.Fatal("the admin API handler must be the mux router")
	}
	if !routes(t, router, http.MethodPost, "/api/v1/tenants/") {
		t.Fatal("the admin API must be mounted before this proves anything")
	}
	if rec := request(t, handlerOf(router), http.MethodGet, "/api/v1/nonexistent"); rec.Code != http.StatusNotFound {
		t.Fatalf("expected the router to answer, got %d", rec.Code)
	}

	if sockets := listeningSockets(t); len(sockets) != 0 {
		t.Fatalf("the admin desktop application must open no listener, found %v", sockets)
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
		if typ.Kind() == reflect.Pointer {
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
// frontend a relative base: no host and no port, so the Svelte transport
// fetches "/admin/..." and "/api/v1/tenants/..." against the window's own
// origin.
func TestApp_GetApiBaseUrl_IsSameOriginRelative(t *testing.T) {
	if base := newTestApp().GetApiBaseUrl(); base != "" {
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
