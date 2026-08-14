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

package rest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

const uiIndexHTML = `<html><body>xkms web ui</body></html>`

// uiTestAssets builds an in-memory vite dist tree.
func uiTestAssets() fstest.MapFS {
	return fstest.MapFS{
		"index.html":    &fstest.MapFile{Data: []byte(uiIndexHTML)},
		"assets/app.js": &fstest.MapFile{Data: []byte("console.log('ui')")},
	}
}

// newUITestServer builds a REST server with the given UI options.
func newUITestServer(t *testing.T, ui *UIOptions) *Server {
	t.Helper()

	server, err := NewServer(&Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": newMockKeyStore()},
		Logger:        testLogger(),
		UI:            ui,
	})
	require.NoError(t, err)
	return server
}

// doUIRequest runs a GET through the full router.
func doUIRequest(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

func TestUIMount_ServesIndexAndFallback(t *testing.T) {
	server := newUITestServer(t, &UIOptions{Enabled: true, Assets: uiTestAssets()})

	for _, path := range []string{"/ui/", "/ui/anything", "/ui/deep/client/route"} {
		w := doUIRequest(t, server, path)
		require.Equal(t, http.StatusOK, w.Code, path)
		assert.Equal(t, uiIndexHTML, w.Body.String(), path)
	}

	static := doUIRequest(t, server, "/ui/assets/app.js")
	require.Equal(t, http.StatusOK, static.Code)
	assert.Equal(t, "console.log('ui')", static.Body.String())
}

func TestUIMount_BarePrefixRedirects(t *testing.T) {
	server := newUITestServer(t, &UIOptions{Enabled: true, Assets: uiTestAssets()})

	w := doUIRequest(t, server, "/ui")
	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/ui/", w.Header().Get("Location"))
}

func TestUIMount_APIRoutesTakePriority(t *testing.T) {
	server := newUITestServer(t, &UIOptions{Enabled: true, Assets: uiTestAssets(), RedirectRoot: true})

	// Public API endpoints must still answer as JSON, never as the SPA shell.
	caps := doUIRequest(t, server, "/api/v1/capabilities")
	require.Equal(t, http.StatusOK, caps.Code)
	assert.Contains(t, caps.Header().Get("Content-Type"), "application/json")
	assert.NotContains(t, caps.Body.String(), "xkms web ui")

	health := doUIRequest(t, server, "/health")
	require.Equal(t, http.StatusOK, health.Code)
	assert.NotContains(t, health.Body.String(), "xkms web ui")
}

func TestUIMount_SecurityHeaders(t *testing.T) {
	server := newUITestServer(t, &UIOptions{Enabled: true, Assets: uiTestAssets()})

	w := doUIRequest(t, server, "/ui/")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "default-src 'self'; frame-ancestors 'none'", w.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))

	// The UI-scoped headers must not bleed onto API responses.
	api := doUIRequest(t, server, "/api/v1/capabilities")
	assert.Empty(t, api.Header().Get("Content-Security-Policy"))
}

func TestUIMount_NoUIConfigured404s(t *testing.T) {
	server := newUITestServer(t, nil)

	w := doUIRequest(t, server, "/ui/")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUIMount_DisabledUI404s(t *testing.T) {
	server := newUITestServer(t, &UIOptions{Enabled: false, Assets: uiTestAssets()})

	w := doUIRequest(t, server, "/ui/")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUIMount_RedirectRoot(t *testing.T) {
	server := newUITestServer(t, &UIOptions{Enabled: true, Assets: uiTestAssets(), RedirectRoot: true})

	w := doUIRequest(t, server, "/")
	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/ui/", w.Header().Get("Location"))
}

func TestUIMount_NoRedirectRootByDefault(t *testing.T) {
	server := newUITestServer(t, &UIOptions{Enabled: true, Assets: uiTestAssets()})

	w := doUIRequest(t, server, "/")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUIMount_CustomPrefix(t *testing.T) {
	server := newUITestServer(t, &UIOptions{
		Enabled:      true,
		Assets:       uiTestAssets(),
		PathPrefix:   "/console/",
		RedirectRoot: true,
	})

	w := doUIRequest(t, server, "/console/")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, uiIndexHTML, w.Body.String())

	root := doUIRequest(t, server, "/")
	require.Equal(t, http.StatusFound, root.Code)
	assert.Equal(t, "/console/", root.Header().Get("Location"))

	if !strings.HasPrefix(root.Header().Get("Location"), "/console") {
		t.Errorf("root redirect points at %q, want the custom prefix", root.Header().Get("Location"))
	}
}
