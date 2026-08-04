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

package webui

import (
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/gorilla/mux"
)

// newTestRouter creates a mux.Router with the SPA handler registered using
// an in-memory filesystem.
func newTestRouter(t *testing.T, files fstest.MapFS) *mux.Router {
	t.Helper()
	router := mux.NewRouter()
	logger := slog.Default()
	if err := RegisterRoutes(router, files, logger); err != nil {
		t.Fatalf("RegisterRoutes: %v", err)
	}
	return router
}

func TestRegisterRoutes_ServesIndexHTML(t *testing.T) {
	files := fstest.MapFS{
		"dist/index.html": &fstest.MapFile{Data: []byte("<html>admin</html>")},
	}
	router := newTestRouter(t, files)

	req := httptest.NewRequest(http.MethodGet, "/ui/admin/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if string(body) != "<html>admin</html>" {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestRegisterRoutes_ServesStaticFile(t *testing.T) {
	files := fstest.MapFS{
		"dist/index.html":       &fstest.MapFile{Data: []byte("<html>admin</html>")},
		"dist/assets/app.js":    &fstest.MapFile{Data: []byte("console.log('app')")},
		"dist/assets/style.css": &fstest.MapFile{Data: []byte("body{}")},
	}
	router := newTestRouter(t, files)

	tests := []struct {
		name string
		path string
		body string
	}{
		{"javascript", "/ui/admin/assets/app.js", "console.log('app')"},
		{"css", "/ui/admin/assets/style.css", "body{}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rec.Code)
			}
			body, _ := io.ReadAll(rec.Body)
			if string(body) != tt.body {
				t.Errorf("expected %q, got %q", tt.body, body)
			}
		})
	}
}

func TestRegisterRoutes_SPAFallback(t *testing.T) {
	files := fstest.MapFS{
		"dist/index.html": &fstest.MapFile{Data: []byte("<html>spa</html>")},
	}
	router := newTestRouter(t, files)

	// Client-side route that does not exist as a file should fall back to index.html
	req := httptest.NewRequest(http.MethodGet, "/ui/admin/dashboard/settings", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if string(body) != "<html>spa</html>" {
		t.Errorf("expected SPA fallback, got %q", body)
	}
}

func TestRegisterRoutes_DirectoryFallsBackToIndex(t *testing.T) {
	// When a request path resolves to a directory without an index.html
	// inside it, the handler should fall back to the root index.html.
	files := fstest.MapFS{
		"dist/index.html":    &fstest.MapFile{Data: []byte("<html>root</html>")},
		"dist/assets/app.js": &fstest.MapFile{Data: []byte("js")},
	}
	router := newTestRouter(t, files)

	// "assets" is a directory in the FS - should fall back to root index.html
	req := httptest.NewRequest(http.MethodGet, "/ui/admin/assets", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if string(body) != "<html>root</html>" {
		t.Errorf("expected root index fallback for directory, got %q", body)
	}
}

func TestRegisterRoutes_DirectoryWithIndex(t *testing.T) {
	// When a directory has its own index.html, it should be served.
	files := fstest.MapFS{
		"dist/index.html":        &fstest.MapFile{Data: []byte("<html>root</html>")},
		"dist/sub/index.html":    &fstest.MapFile{Data: []byte("<html>sub</html>")},
		"dist/sub/other-file.js": &fstest.MapFile{Data: []byte("js")},
	}
	router := newTestRouter(t, files)

	req := httptest.NewRequest(http.MethodGet, "/ui/admin/sub", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if string(body) != "<html>sub</html>" {
		t.Errorf("expected sub directory index, got %q", body)
	}
}

// brokenSubFS implements fs.SubFS with an Open method that always fails,
// causing fs.Sub to return the error from the SubFS implementation.
type brokenSubFS struct{}

// Open satisfies the fs.FS interface.
func (brokenSubFS) Open(string) (fs.File, error) {
	return nil, errors.New("broken filesystem")
}

// Sub satisfies the fs.SubFS interface, causing fs.Sub to delegate to it.
func (brokenSubFS) Sub(string) (fs.FS, error) {
	return nil, errors.New("broken sub filesystem")
}

func TestRegisterRoutes_InvalidAssets(t *testing.T) {
	router := mux.NewRouter()
	logger := slog.Default()
	err := RegisterRoutes(router, brokenSubFS{}, logger)
	if err == nil {
		t.Fatal("expected error for broken filesystem")
	}
	if _, ok := err.(*ErrAssetLoad); !ok {
		t.Errorf("expected *ErrAssetLoad, got %T: %v", err, err)
	}
}

func TestRegisterRoutes_MissingIndexFallback(t *testing.T) {
	// Filesystem with dist but no index.html - SPA fallback should 404
	files := fstest.MapFS{
		"dist/assets/app.js": &fstest.MapFile{Data: []byte("js")},
	}
	router := newTestRouter(t, files)

	req := httptest.NewRequest(http.MethodGet, "/ui/admin/nonexistent", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when index.html is missing, got %d", rec.Code)
	}
}

func TestRegisterRoutes_DirectoryMissingIndex(t *testing.T) {
	// Directory without its own index.html and no root index.html - should 404
	files := fstest.MapFS{
		"dist/assets/app.js": &fstest.MapFile{Data: []byte("js")},
	}
	router := newTestRouter(t, files)

	// "assets" is a directory, no index.html anywhere
	req := httptest.NewRequest(http.MethodGet, "/ui/admin/assets", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for directory without index, got %d", rec.Code)
	}
}

func TestRegisterRoutes_RootRedirectsToIndex(t *testing.T) {
	files := fstest.MapFS{
		"dist/index.html": &fstest.MapFile{Data: []byte("<html>root</html>")},
	}
	router := newTestRouter(t, files)

	// Request to bare /ui/admin/ should serve index.html
	req := httptest.NewRequest(http.MethodGet, "/ui/admin/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if string(body) != "<html>root</html>" {
		t.Errorf("expected root index, got %q", body)
	}
}

func TestRegisterRoutes_DeepNestedSPARoute(t *testing.T) {
	files := fstest.MapFS{
		"dist/index.html": &fstest.MapFile{Data: []byte("<html>spa</html>")},
	}
	router := newTestRouter(t, files)

	// Deeply nested SPA route should still fall back to index.html
	req := httptest.NewRequest(http.MethodGet, "/ui/admin/a/b/c/d/e", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for deep SPA route, got %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if string(body) != "<html>spa</html>" {
		t.Errorf("expected SPA fallback, got %q", body)
	}
}
