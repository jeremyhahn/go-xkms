// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-chi/chi/v5"
)

// indexHTML is a minimal SPA shell with the </head> anchor the API-base-URL
// injection targets.
const indexHTML = `<!doctype html><html><head><title>xkms</title></head><body><div id="app"></div></body></html>`

// distFS builds an in-memory dist filesystem with an index.html shell and a
// couple of static assets.
func distFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":       &fstest.MapFile{Data: []byte(indexHTML), ModTime: time.Unix(1700000000, 0)},
		"assets/app.js":    &fstest.MapFile{Data: []byte("console.log('app')")},
		"assets/style.css": &fstest.MapFile{Data: []byte("body{margin:0}")},
	}
}

// newChiRouter mounts the SPA on a fresh chi router at the given prefix.
func newChiRouter(t *testing.T, assets fs.FS, prefix string, opts ...Option) chi.Router {
	t.Helper()
	r := chi.NewRouter()
	if err := MountChi(r, assets, prefix, slog.Default(), opts...); err != nil {
		t.Fatalf("MountChi: %v", err)
	}
	return r
}

// get performs a GET against the handler and returns the recorder.
func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestNewHandler_NilAssets(t *testing.T) {
	h, err := NewHandler(nil, slog.Default())
	if h != nil {
		t.Error("expected nil handler for nil assets")
	}
	var nilErr *ErrNilAssets
	if !errors.As(err, &nilErr) {
		t.Fatalf("error type = %T, want *ErrNilAssets", err)
	}
}

func TestNewHandler_NilLoggerDefaults(t *testing.T) {
	h, err := NewHandler(distFS(), nil)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	rec := get(t, h, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestNewHandler_ServesIndexAndAssets(t *testing.T) {
	h, err := NewHandler(distFS(), slog.Default())
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	tests := []struct {
		name        string
		path        string
		body        string
		contentType string
	}{
		{"index", "/", indexHTML, "text/html"},
		{"javascript", "/assets/app.js", "console.log('app')", "javascript"},
		{"css", "/assets/style.css", "body{margin:0}", "text/css"},
		{"spa fallback", "/dashboard/settings", indexHTML, "text/html"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := get(t, h, tt.path)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if rec.Body.String() != tt.body {
				t.Errorf("body = %q, want %q", rec.Body.String(), tt.body)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, tt.contentType) {
				t.Errorf("Content-Type = %q, want to contain %q", ct, tt.contentType)
			}
		})
	}
}

func TestNewHandler_NoDirectoryListing(t *testing.T) {
	// A directory without its own index.html must fall back to the root
	// shell, never render a listing of its contents.
	h, err := NewHandler(distFS(), slog.Default())
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	rec := get(t, h, "/assets")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != indexHTML {
		t.Errorf("directory request served %q, want the root index fallback", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "app.js") {
		t.Error("a directory listing leaked asset names")
	}
}

func TestNewHandler_DirectoryWithOwnIndex(t *testing.T) {
	files := distFS()
	files["sub/index.html"] = &fstest.MapFile{Data: []byte("<html>sub</html>")}
	h, err := NewHandler(files, slog.Default())
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	rec := get(t, h, "/sub")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "<html>sub</html>" {
		t.Errorf("body = %q, want the directory's own index", rec.Body.String())
	}
}

func TestNewHandler_MissingIndexIs404(t *testing.T) {
	files := fstest.MapFS{
		"assets/app.js": &fstest.MapFile{Data: []byte("//")},
	}
	h, err := NewHandler(files, slog.Default())
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	rec := get(t, h, "/nonexistent")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when index.html is missing", rec.Code)
	}
}

func TestWithAPIBaseURL_InjectsBeforeHead(t *testing.T) {
	h, err := NewHandler(distFS(), slog.Default(), WithAPIBaseURL("/api/v1"))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	rec := get(t, h, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	const want = `<script>window.__API_BASE_URL__="/api/v1";</script>`
	if !strings.Contains(body, want+"</head>") {
		t.Fatalf("the script was not placed immediately before </head>:\n%s", body)
	}
	if strings.Count(body, "window.__API_BASE_URL__") != 1 {
		t.Errorf("the injection was applied %d times, want exactly once", strings.Count(body, "window.__API_BASE_URL__"))
	}
	if !strings.Contains(body, `<div id="app"></div>`) {
		t.Error("the SPA shell was corrupted by the injection")
	}
}

func TestWithAPIBaseURL_LeavesRealAssetsAlone(t *testing.T) {
	h, err := NewHandler(distFS(), slog.Default(), WithAPIBaseURL("/api/v1"))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	rec := get(t, h, "/assets/app.js")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "__API_BASE_URL__") {
		t.Error("the injection leaked into a JavaScript asset")
	}
}

func TestWithAPIBaseURL_EmptyValueDisablesInjection(t *testing.T) {
	h, err := NewHandler(distFS(), slog.Default(), WithAPIBaseURL(""))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	rec := get(t, h, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "__API_BASE_URL__") {
		t.Error("an empty base URL still produced an injection")
	}
	if rec.Header().Get("Last-Modified") == "" {
		t.Error("the uninjected path should go through http.ServeContent, which sets Last-Modified")
	}
}

func TestNormalizePrefix(t *testing.T) {
	tests := []struct {
		name    string
		prefix  string
		want    string
		wantErr bool
	}{
		{"empty selects default", "", DefaultPathPrefix, false},
		{"trailing slash kept", "/ui/", "/ui/", false},
		{"trailing slash added", "/console", "/console/", false},
		{"root", "/", "/", false},
		{"relative rejected", "ui/", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizePrefix(tt.prefix)
			if tt.wantErr {
				var invalidErr *ErrInvalidPrefix
				if !errors.As(err, &invalidErr) {
					t.Fatalf("error type = %T, want *ErrInvalidPrefix", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizePrefix(%q): %v", tt.prefix, err)
			}
			if got != tt.want {
				t.Errorf("NormalizePrefix(%q) = %q, want %q", tt.prefix, got, tt.want)
			}
		})
	}
}

func TestMountChi_ServesUnderPrefix(t *testing.T) {
	r := newChiRouter(t, distFS(), "/ui/")

	for _, path := range []string{"/ui/", "/ui/assets/app.js", "/ui/deep/client/route"} {
		rec := get(t, r, path)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", path, rec.Code)
		}
	}
}

func TestMountChi_DefaultPrefix(t *testing.T) {
	r := newChiRouter(t, distFS(), "")
	rec := get(t, r, "/ui/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 at the default prefix", rec.Code)
	}
}

func TestMountChi_BarePrefixRedirects(t *testing.T) {
	r := newChiRouter(t, distFS(), "/ui/")
	rec := get(t, r, "/ui")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 for the bare prefix", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/ui/" {
		t.Errorf("Location = %q, want /ui/", loc)
	}
}

func TestMountChi_CustomPrefixWithoutTrailingSlash(t *testing.T) {
	r := newChiRouter(t, distFS(), "/console")
	rec := get(t, r, "/console/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	redir := get(t, r, "/console")
	if redir.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 for the bare prefix", redir.Code)
	}
	if loc := redir.Header().Get("Location"); loc != "/console/" {
		t.Errorf("Location = %q, want /console/", loc)
	}
}

func TestMountChi_APIBaseURLInjection(t *testing.T) {
	r := newChiRouter(t, distFS(), "/ui/", WithAPIBaseURL("/api/v1"))
	rec := get(t, r, "/ui/tenants/alpha")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `window.__API_BASE_URL__="/api/v1"`) {
		t.Error("the SPA fallback served an uninjected shell")
	}
}

func TestMountChi_NilRouter(t *testing.T) {
	err := MountChi(nil, distFS(), "/ui/", slog.Default())
	var nilErr *ErrNilRouter
	if !errors.As(err, &nilErr) {
		t.Fatalf("error type = %T, want *ErrNilRouter", err)
	}
}

func TestMountChi_NilAssets(t *testing.T) {
	err := MountChi(chi.NewRouter(), nil, "/ui/", slog.Default())
	var nilErr *ErrNilAssets
	if !errors.As(err, &nilErr) {
		t.Fatalf("error type = %T, want *ErrNilAssets", err)
	}
}

func TestMountChi_InvalidPrefix(t *testing.T) {
	err := MountChi(chi.NewRouter(), distFS(), "no-slash", slog.Default())
	var invalidErr *ErrInvalidPrefix
	if !errors.As(err, &invalidErr) {
		t.Fatalf("error type = %T, want *ErrInvalidPrefix", err)
	}
	if !strings.Contains(err.Error(), "no-slash") {
		t.Errorf("error %q does not name the offending prefix", err)
	}
}

func TestErrorMessages(t *testing.T) {
	if msg := (&ErrNilAssets{}).Error(); !strings.Contains(msg, "assets") {
		t.Errorf("ErrNilAssets message %q does not mention assets", msg)
	}
	if msg := (&ErrNilRouter{}).Error(); !strings.Contains(msg, "router") {
		t.Errorf("ErrNilRouter message %q does not mention the router", msg)
	}
	if msg := (&ErrInvalidPrefix{Prefix: "xyz"}).Error(); !strings.Contains(msg, "xyz") {
		t.Errorf("ErrInvalidPrefix message %q does not carry the prefix", msg)
	}
}
