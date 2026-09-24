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
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// newModuleRESTServerWithUI builds a *rest.Server with the embedded web UI
// enabled and serving fsys under prefix, mirroring newModuleRESTServer's
// no-UI default so tests can exercise the UI-configured branches of
// lazyUIHandler.
func newModuleRESTServerWithUI(t *testing.T, prefix string, redirectRoot bool, fsys fstest.MapFS) *rest.Server {
	t.Helper()
	srv, err := rest.NewServer(&rest.Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		UI: &rest.UIOptions{
			Enabled:      true,
			PathPrefix:   prefix,
			Assets:       fsys,
			RedirectRoot: redirectRoot,
		},
	})
	require.NoError(t, err)
	return srv
}

// TestRegisterHTTP_NoUIByDefault proves the crypto-plane module registers no
// "/ui" route unless WithWebUI is supplied.
func TestRegisterHTTP_NoUIByDefault(t *testing.T) {
	m, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	for _, r := range *recs {
		assert.NotContains(t, r.pattern, "/ui", "no UI route should register without WithWebUI")
	}
}

// TestRegisterHTTP_WithWebUI_RegistersUIAndRootRedirect proves WithWebUI
// mounts the UI's prefix, its wildcard, and — when redirectRoot is set — a
// public GET / redirect, exactly like the admin module's own UI wiring.
func TestRegisterHTTP_WithWebUI_RegistersUIAndRootRedirect(t *testing.T) {
	const uiPrefix = "/ui"
	fsys := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>xkms ui</html>")}}
	srv := newModuleRESTServerWithUI(t, uiPrefix, true, fsys)

	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithRESTServer(func() *rest.Server { return srv }),
		WithWebUI(uiPrefix, true))
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	var uiHandler, rootHandler http.HandlerFunc
	for _, r := range *recs {
		if r.method == http.MethodGet && r.pattern == uiPrefix+"/*" {
			uiHandler = r.handler
		}
		if r.method == http.MethodGet && r.pattern == "/" {
			rootHandler = r.handler
		}
	}
	require.NotNil(t, uiHandler, "%s/* must be registered", uiPrefix)
	require.NotNil(t, rootHandler, "GET / must be registered when redirectRoot is set")

	w := httptest.NewRecorder()
	uiHandler(w, httptest.NewRequest(http.MethodGet, uiPrefix+"/", nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "xkms ui")

	w = httptest.NewRecorder()
	rootHandler(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, uiPrefix, w.Header().Get("Location"))
}

// TestLazyUIHandler_ComposingThenResolvedNoUIThenServed exercises all three
// observable states of the UI handler in sequence against ONE handler
// instance, proving its memoization behaves correctly across them: 503
// while the host is still composing (no REST server resolved yet), 404 once
// resolved against a server with no UI configured, and a served response
// once resolved against a server that does carry one.
func TestLazyUIHandler_ComposingThenResolvedNoUIThenServed(t *testing.T) {
	var srv atomic.Pointer[rest.Server]
	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithRESTServer(func() *rest.Server { return srv.Load() }),
		WithWebUI("/ui", false))
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	var uiHandler http.HandlerFunc
	for _, r := range *recs {
		if r.method == http.MethodGet && r.pattern == "/ui/*" {
			uiHandler = r.handler
		}
	}
	require.NotNil(t, uiHandler)

	// Still composing: WithRESTServer resolver returns nil.
	w := httptest.NewRecorder()
	uiHandler(w, httptest.NewRequest(http.MethodGet, "/ui/", nil))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	// Resolved, but the server carries no UI.
	srv.Store(newModuleRESTServer(t))
	w = httptest.NewRecorder()
	uiHandler(w, httptest.NewRequest(http.MethodGet, "/ui/", nil))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestLazyUIHandler_ServesConfiguredUI proves that once the resolved server
// carries a configured UI, the handler serves its real content.
func TestLazyUIHandler_ServesConfiguredUI(t *testing.T) {
	fsys := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html>served</html>")}}
	srv := newModuleRESTServerWithUI(t, "/ui", false, fsys)
	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithRESTServer(func() *rest.Server { return srv }),
		WithWebUI("/ui", false))
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	var uiHandler http.HandlerFunc
	for _, r := range *recs {
		if r.method == http.MethodGet && r.pattern == "/ui/*" {
			uiHandler = r.handler
		}
	}
	require.NotNil(t, uiHandler)

	w := httptest.NewRecorder()
	uiHandler(w, httptest.NewRequest(http.MethodGet, "/ui/", nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "served")

	// A second request must hit the memoized fast path (bound.Load() != nil)
	// rather than re-resolving the REST server and re-binding the handler.
	w = httptest.NewRecorder()
	uiHandler(w, httptest.NewRequest(http.MethodGet, "/ui/", nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "served")
}

// TestLazyUIHandler_HostBuildFailure proves the UI handler surfaces a
// restServer() construction failure (the self-built path with no usable
// host inputs) as a 503 naming the failure, rather than treating it the
// same as "still composing".
func TestLazyUIHandler_HostBuildFailure(t *testing.T) {
	m, err := NewModule(func() *xkms.XKMSService { return &xkms.XKMSService{} },
		WithWebUI("/ui", false))
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	var uiHandler http.HandlerFunc
	for _, r := range *recs {
		if r.method == http.MethodGet && r.pattern == "/ui/*" {
			uiHandler = r.handler
		}
	}
	require.NotNil(t, uiHandler)

	w := httptest.NewRecorder()
	uiHandler(w, httptest.NewRequest(http.MethodGet, "/ui/", nil))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "host provided no usable REST inputs")
}

// TestModule_AuthenticateHTTP_StillComposing proves AuthenticateHTTP fails
// closed with *SurfaceComposingError, rather than a nil identity and nil
// error, while the module has no REST surface to authenticate against yet
// (no WithRESTServer resolver, and the service resolver has not yielded a
// service for the self-built path to build from either).
func TestModule_AuthenticateHTTP_StillComposing(t *testing.T) {
	m, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)

	identity, authErr := m.AuthenticateHTTP(httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil))
	assert.Nil(t, identity)
	var composing *SurfaceComposingError
	require.ErrorAs(t, authErr, &composing)
	assert.Equal(t, "authentication", composing.Surface)
}

// hostBuildTestCause is a distinct concrete error type so
// TestHostBuildError_Unwrap's errors.As can only succeed by actually
// traversing HostBuildError.Unwrap — an errors.As target of the bare error
// interface would match the wrapper itself without ever calling Unwrap.
type hostBuildTestCause struct{ msg string }

func (e *hostBuildTestCause) Error() string { return e.msg }

// TestHostBuildError_Unwrap proves errors.Is/errors.As can see through a
// *HostBuildError to the construction failure it wraps, which is what lets
// a caller distinguish specific rest.NewHostServer failures (e.g. a missing
// signing backend) rather than only matching the wrapper type.
func TestHostBuildError_Unwrap(t *testing.T) {
	cause := &hostBuildTestCause{msg: "no signing backend configured"}
	err := &HostBuildError{Err: cause}

	assert.ErrorIs(t, err, cause)

	var asCause *hostBuildTestCause
	require.True(t, errors.As(err, &asCause), "errors.As must traverse Unwrap to reach the concrete cause type")
	assert.Same(t, cause, asCause)
}
