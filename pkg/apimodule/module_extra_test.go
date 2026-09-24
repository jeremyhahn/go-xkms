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

package apimodule

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// TestModule_MCPToolPermissions proves every module MCP tool declares a
// permission qrdb's MCP authorization path can enforce: a permission-mapped
// method's tool carries its exact "resource:action" pair, and every other
// method (public or handler-gated) carries the identity-gated sentinel —
// never an empty permission, which the unified server's MCP registry would
// otherwise have to interpret as default-deny or, worse, default-allow.
func TestModule_MCPToolPermissions(t *testing.T) {
	m, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)

	specs := xkmsmcp.ModuleMethods()
	require.NotEmpty(t, specs, "the module MCP method table must not be empty")

	perms := m.MCPToolPermissions()
	require.Len(t, perms, len(specs), "one permission entry per distinct tool")

	var sawPermissionMapped, sawIdentityGated bool
	for _, spec := range specs {
		perm, ok := perms[spec.Tool]
		require.True(t, ok, "tool %q missing from MCPToolPermissions", spec.Tool)
		assert.NotEmpty(t, string(perm), "tool %q must never carry an empty permission", spec.Tool)

		if spec.Resource != "" && spec.Action != "" {
			assert.Equal(t, qrdbsdk.Permission(spec.Resource+":"+spec.Action), perm,
				"tool %q must carry its exact resource:action pair", spec.Tool)
			sawPermissionMapped = true
			continue
		}
		assert.Equal(t, qrdbsdk.PermissionIdentityGated, perm,
			"public/handler-gated tool %q must carry the identity-gated sentinel", spec.Tool)
		sawIdentityGated = true
	}
	assert.True(t, sawPermissionMapped, "expected at least one permission-mapped tool in the fixture")
	assert.True(t, sawIdentityGated, "expected at least one identity-gated tool in the fixture")
}

// TestModule_PublicGRPCMethods pins the exact set of KeystoreService RPCs
// admitted into qrdb's unified-server gRPC interceptor without
// authentication. xkms.proto leaves Health and Algorithms unannotated with
// (qrdb.v1.permission), so a regression that drops an entry here silently
// DEFAULT-DENYs that RPC instead of failing a test — the doc comment on
// PublicGRPCMethods spells out exactly this failure mode.
func TestModule_PublicGRPCMethods(t *testing.T) {
	m, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)

	got := m.PublicGRPCMethods()
	want := []string{
		"/xkms.v1.KeystoreService/Health",
		"/xkms.v1.KeystoreService/Algorithms",
	}
	assert.Equal(t, want, got)
}

// TestModule_WithSessionOptionsAndPIVLogin_Plumbed proves WithSessionOptions
// and WithPIVLogin reach the module's self-built REST surface
// (rest.NewHostServer) rather than being accepted and silently dropped: a
// host that configures PIV login must see it reflected on the surface the
// module actually serves.
func TestModule_WithSessionOptionsAndPIVLogin_Plumbed(t *testing.T) {
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	m, err := NewModule(func() *xkms.XKMSService { return svc },
		WithSessionOptions(&rest.SessionOptions{Issuer: "xkms-test-issuer", LoginRatePerMin: 5}),
		WithPIVLogin(&rest.PIVLoginOptions{Enabled: true}))
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	var capabilities http.HandlerFunc
	for _, rec := range *recs {
		if rec.method == "GET" && rec.pattern == "/api/v1/capabilities" {
			capabilities = rec.handler
		}
	}
	require.NotNil(t, capabilities, "GET /api/v1/capabilities must be registered")

	w := httptest.NewRecorder()
	capabilities(w, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp struct {
		PIVLoginEnabled bool `json:"piv_login_enabled"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.PIVLoginEnabled,
		"WithPIVLogin(Enabled: true) must be reflected on the self-built surface's capabilities")
}

// TestModule_WithWebUI_ServesFromResolvedRESTServer proves WithWebUI mounts
// the SPA on the module's own prefix and lazyUIHandler forwards to the
// resolved REST server's real UI handler and content, plus registers the
// root redirect when requested.
func TestModule_WithWebUI_ServesFromResolvedRESTServer(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html>xkms ui</html>")},
	}
	srv, err := rest.NewServer(&rest.Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		UI: &rest.UIOptions{
			Enabled:    true,
			PathPrefix: "/ui",
			Assets:     fsys,
		},
	})
	require.NoError(t, err)

	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithRESTServer(func() *rest.Server { return srv }),
		WithWebUI("/ui", true))
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	var ui, root http.HandlerFunc
	for _, rec := range *recs {
		switch {
		case rec.method == "GET" && rec.pattern == "/ui/*":
			ui = rec.handler
		case rec.method == "GET" && rec.pattern == "/":
			root = rec.handler
		}
	}
	require.NotNil(t, ui, "GET /ui/* must be registered")
	require.NotNil(t, root, "GET / redirect must be registered when redirectRoot is set")

	w := httptest.NewRecorder()
	ui(w, httptest.NewRequest(http.MethodGet, "/ui/", nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "xkms ui")

	w = httptest.NewRecorder()
	root(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/ui", w.Header().Get("Location"))
}

// TestModule_WithWebUI_ComposingServer503 proves the UI route answers 503
// while the REST resolver has not yet produced a server, exactly like the
// API route family, rather than a nil-pointer panic or a silent 404.
func TestModule_WithWebUI_ComposingServer503(t *testing.T) {
	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithRESTServer(func() *rest.Server { return nil }),
		WithWebUI("/ui", false))
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	var ui http.HandlerFunc
	for _, rec := range *recs {
		if rec.method == "GET" && rec.pattern == "/ui/*" {
			ui = rec.handler
		}
	}
	require.NotNil(t, ui)

	w := httptest.NewRecorder()
	ui(w, httptest.NewRequest(http.MethodGet, "/ui/", nil))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "still composing")
}

// TestAdminModule_RegisterHTTP_RootRedirect proves WithAdminWebUI's
// redirectRoot option registers GET / redirecting to the admin UI prefix —
// the one RegisterHTTP branch the existing admin module tests configure
// with redirectRoot left false.
func TestAdminModule_RegisterHTTP_RootRedirect(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html>admin ui</html>")},
	}
	m, err := NewAdminModule(func() http.Handler { return nil }, []string{"/admin"},
		WithAdminWebUI("/admin-ui", fsys, true))
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	var root http.HandlerFunc
	for _, rec := range *recs {
		if rec.method == http.MethodGet && rec.pattern == "/" {
			root = rec.handler
		}
	}
	require.NotNil(t, root, "GET / redirect must be registered when redirectRoot is set")

	w := httptest.NewRecorder()
	root(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/admin-ui", w.Header().Get("Location"))
}
