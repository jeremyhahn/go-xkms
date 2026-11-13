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
	"io"
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
