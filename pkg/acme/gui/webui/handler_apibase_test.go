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

	"github.com/gorilla/mux"
)

// indexHTML is a minimal SPA shell with the </head> anchor the API-base-URL
// injection targets.
const indexHTML = `<!doctype html><html><head><title>admin</title></head><body><div id="app"></div></body></html>`

// newSPARouter registers the SPA at /ui/admin/ with the given options and
// returns the router.
func newSPARouter(t *testing.T, files fs.FS, opts ...SPAOption) *mux.Router {
	t.Helper()
	router := mux.NewRouter()
	if err := RegisterSPA(router, files, "/ui/admin/", slog.Default(), opts...); err != nil {
		t.Fatalf("RegisterSPA: %v", err)
	}
	return router
}

// get performs a GET against the router and returns the recorder.
func get(t *testing.T, router *mux.Router, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// TestWithAPIBaseURL_InjectsBeforeHead covers the API-base-URL injection that
// lets the built SPA discover the server's API prefix at runtime. The bundle
// is compiled without knowing its mount point, so a broken injection leaves
// the admin UI unable to reach any endpoint.
func TestWithAPIBaseURL_InjectsBeforeHead(t *testing.T) {
	files := fstest.MapFS{
		"dist/index.html": &fstest.MapFile{Data: []byte(indexHTML)},
	}
	router := newSPARouter(t, files, WithAPIBaseURL("/api/v1"))

	rec := get(t, router, "/ui/admin/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	const want = `<script>window.__API_BASE_URL__="/api/v1";</script>`
	if !strings.Contains(body, want) {
		t.Fatalf("injected script missing from:\n%s", body)
	}
	if strings.Count(body, "window.__API_BASE_URL__") != 1 {
		t.Errorf("the injection was applied %d times, want exactly once", strings.Count(body, "window.__API_BASE_URL__"))
	}
	// It must land inside <head>, before the closing tag, or the SPA bundle
	// (loaded later in the document) would run before the global is set.
	if !strings.Contains(body, want+"</head>") {
		t.Errorf("the script was not placed immediately before </head>:\n%s", body)
	}
	if strings.Index(body, want) > strings.Index(body, "<body>") {
		t.Error("the script was injected after <body>")
	}
	// The original document must survive intact.
	if !strings.Contains(body, `<div id="app"></div>`) {
		t.Error("the SPA shell was corrupted by the injection")
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

// TestWithAPIBaseURL_InjectsOnSPAFallbackRoutes verifies deep client-side
// routes get the injection too. Those are the URLs an operator actually
// bookmarks; serving them an uninjected shell would make the UI work only
// when entered from the root.
func TestWithAPIBaseURL_InjectsOnSPAFallbackRoutes(t *testing.T) {
	files := fstest.MapFS{
		"dist/index.html": &fstest.MapFile{Data: []byte(indexHTML)},
	}
	router := newSPARouter(t, files, WithAPIBaseURL("https://ca.example.com/api"))

	for _, path := range []string{
		"/ui/admin/",
		"/ui/admin/tenants",
		"/ui/admin/tenants/alpha/certificates",
		"/ui/admin/does/not/exist",
	} {
		rec := get(t, router, path)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", path, rec.Code)
			continue
		}
		if !strings.Contains(rec.Body.String(), `window.__API_BASE_URL__="https://ca.example.com/api"`) {
			t.Errorf("%s: served an uninjected shell", path)
		}
	}
}

// TestWithAPIBaseURL_LeavesRealAssetsAlone proves the injection is confined to
// the HTML shell. Rewriting a JavaScript or CSS asset would corrupt the bundle.
func TestWithAPIBaseURL_LeavesRealAssetsAlone(t *testing.T) {
	const js = `console.log("</head>");`
	files := fstest.MapFS{
		"dist/index.html":     &fstest.MapFile{Data: []byte(indexHTML)},
		"dist/assets/app.js":  &fstest.MapFile{Data: []byte(js)},
		"dist/assets/app.css": &fstest.MapFile{Data: []byte("body{margin:0}")},
	}
	router := newSPARouter(t, files, WithAPIBaseURL("/api/v1"))

	rec := get(t, router, "/ui/admin/assets/app.js")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != js {
		t.Errorf("the JS asset was modified: %q", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "__API_BASE_URL__") {
		t.Error("the injection leaked into a JavaScript asset")
	}

	css := get(t, router, "/ui/admin/assets/app.css")
	if css.Body.String() != "body{margin:0}" {
		t.Errorf("the CSS asset was modified: %q", css.Body.String())
	}
}

// TestWithAPIBaseURL_NoHeadTagLeavesDocumentUnchanged covers the case where
// the shell has no </head> anchor. The replacement is a no-op, and the
// document must be served verbatim rather than truncated or emptied.
func TestWithAPIBaseURL_NoHeadTagLeavesDocumentUnchanged(t *testing.T) {
	const noHead = `<!doctype html><html><body>no head here</body></html>`
	files := fstest.MapFS{
		"dist/index.html": &fstest.MapFile{Data: []byte(noHead)},
	}
	router := newSPARouter(t, files, WithAPIBaseURL("/api/v1"))

	rec := get(t, router, "/ui/admin/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != noHead {
		t.Errorf("body = %q, want the document unchanged", rec.Body.String())
	}
}

// TestWithAPIBaseURL_EmptyValueDisablesInjection confirms the option is opt-in:
// an empty base URL must take the plain http.ServeContent path (which sets
// Last-Modified and supports range requests) rather than rewriting the body.
func TestWithAPIBaseURL_EmptyValueDisablesInjection(t *testing.T) {
	files := fstest.MapFS{
		"dist/index.html": &fstest.MapFile{Data: []byte(indexHTML), ModTime: time.Unix(1700000000, 0)},
	}
	router := newSPARouter(t, files, WithAPIBaseURL(""))

	rec := get(t, router, "/ui/admin/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "__API_BASE_URL__") {
		t.Error("an empty base URL still produced an injection")
	}
	if rec.Body.String() != indexHTML {
		t.Errorf("body = %q, want the document unchanged", rec.Body.String())
	}
	if rec.Header().Get("Last-Modified") == "" {
		t.Error("the uninjected path should go through http.ServeContent, which sets Last-Modified")
	}
}

// TestWithAPIBaseURL_MissingIndexIs404 covers the failure branch of the
// injected path: with no index.html there is nothing to inject into, and the
// handler must report 404 rather than serving an empty 200.
func TestWithAPIBaseURL_MissingIndexIs404(t *testing.T) {
	files := fstest.MapFS{
		"dist/assets/app.js": &fstest.MapFile{Data: []byte("//")},
	}
	router := newSPARouter(t, files, WithAPIBaseURL("/api/v1"))

	rec := get(t, router, "/ui/admin/")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "index.html not found") {
		t.Errorf("body = %q, want a message naming the missing file", rec.Body.String())
	}
}

// TestRegisterSPA_RejectsUnusableAssetRoot covers the constructor's error
// path. fs.Sub rejects an invalid subdirectory name, and RegisterSPA must
// convert that into the package's typed asset-load error rather than
// registering a route that would 404 for every request.
func TestRegisterSPA_RejectsUnusableAssetRoot(t *testing.T) {
	router := mux.NewRouter()
	err := RegisterSPA(router, badSubFS{}, "/ui/admin/", slog.Default())
	if err == nil {
		t.Fatal("RegisterSPA accepted an asset root whose dist subtree cannot be opened")
	}
	var assetErr *ErrAssetLoad
	if !errors.As(err, &assetErr) {
		t.Fatalf("error type = %T, want *ErrAssetLoad", err)
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("error %q does not carry the underlying cause", err)
	}
}

// badSubFS fails fs.Sub by rejecting the Sub operation outright.
type badSubFS struct{}

func (badSubFS) Open(string) (fs.File, error) { return nil, fs.ErrNotExist }
func (badSubFS) Sub(string) (fs.FS, error)    { return nil, errBoom{} }

type errBoom struct{}

func (errBoom) Error() string { return "boom" }
