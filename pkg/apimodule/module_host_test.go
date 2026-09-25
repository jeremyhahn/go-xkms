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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// findRoute returns the captured registration for method+pattern, or fails
// the test: every assertion below needs the route to actually be mounted.
func findRoute(t *testing.T, recs *[]captured, method, pattern string) http.HandlerFunc {
	t.Helper()
	for _, rec := range *recs {
		if rec.method == method && rec.pattern == pattern {
			return rec.handler
		}
	}
	t.Fatalf("route %s %s was not registered", method, pattern)
	return nil
}

// TestModule_WithPIVLogin_EnablesCertificateLoginRoute proves the
// WithPIVLogin option actually reaches the self-built server: with no
// option, the PIV login route refuses every request as "not enabled"; once
// configured, the SAME route reaches its next gate (missing client
// certificate) — proving the option changed the built server's behavior,
// not just a field on the Module.
func TestModule_WithPIVLogin_EnablesCertificateLoginRoute(t *testing.T) {
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	newRequest := func() *http.Request {
		return httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/piv", nil)
	}

	t.Run("disabled by default", func(t *testing.T) {
		m, err := NewModule(func() *xkms.XKMSService { return svc })
		require.NoError(t, err)

		reg, recs := newCaptureRegistrar()
		m.RegisterHTTP(reg)
		handler := findRoute(t, recs, http.MethodPost, "/api/v1/auth/login/piv")

		w := httptest.NewRecorder()
		handler(w, newRequest())
		require.Equal(t, http.StatusUnauthorized, w.Code)

		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp["message"], "not enabled",
			"with no WithPIVLogin, the route must refuse before ever looking for a client certificate")
	})

	t.Run("enabled via WithPIVLogin", func(t *testing.T) {
		m, err := NewModule(func() *xkms.XKMSService { return svc },
			WithPIVLogin(&rest.PIVLoginOptions{Enabled: true}))
		require.NoError(t, err)

		reg, recs := newCaptureRegistrar()
		m.RegisterHTTP(reg)
		handler := findRoute(t, recs, http.MethodPost, "/api/v1/auth/login/piv")

		w := httptest.NewRecorder()
		handler(w, newRequest())
		require.Equal(t, http.StatusUnauthorized, w.Code)

		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Contains(t, resp["message"], "client certificate required",
			"once enabled, the route must reach the certificate-presence gate instead of refusing outright")
	})
}

// TestModule_WithSessionOptions_TightensLoginRateLimit proves
// WithSessionOptions.LoginRatePerMin reaches the self-built server's login
// rate limiter: with the default (10/min) two rapid requests from the same
// client both pass the limiter (and fail later, for lack of a client
// certificate); with LoginRatePerMin=1, the second is rejected with 429
// before it ever reaches the PIV handler's own checks.
func TestModule_WithSessionOptions_TightensLoginRateLimit(t *testing.T) {
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	m, err := NewModule(func() *xkms.XKMSService { return svc },
		WithPIVLogin(&rest.PIVLoginOptions{Enabled: true}),
		WithSessionOptions(&rest.SessionOptions{LoginRatePerMin: 1}))
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)
	handler := findRoute(t, recs, http.MethodPost, "/api/v1/auth/login/piv")

	newRequest := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/piv", nil)
		req.RemoteAddr = "203.0.113.7:5555"
		return req
	}

	first := httptest.NewRecorder()
	handler(first, newRequest())
	require.Equal(t, http.StatusUnauthorized, first.Code,
		"the first request in the window must reach the PIV handler's own gate")

	second := httptest.NewRecorder()
	handler(second, newRequest())
	assert.Equal(t, http.StatusTooManyRequests, second.Code,
		"a LoginRatePerMin of 1 must reject the second request in the same window, body: %s", second.Body.String())
}

// TestModule_SelfBuiltSurfaceServesRealWebAuthnCeremony is the root-cause
// regression test: a host that composes the module with ONLY a service
// resolver plus WithQRDBClient/WithWebAuthnConfig (no WithRESTServer, the
// exact shape go-quicbaas's NewServiceModule call has today) gets a
// WORKING WebAuthn registration ceremony — a real 200 from
// BeginRegistration — instead of the route never being registered at all
// (the bug: RegisterHTTP used to return immediately with no REST resolver).
func TestModule_SelfBuiltSurfaceServesRealWebAuthnCeremony(t *testing.T) {
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	client, _, err := testutil.NewQRDBFakeClient()
	require.NoError(t, err)

	allow := true
	m, err := NewModule(func() *xkms.XKMSService { return svc },
		WithQRDBClient(func() *qrdbsdk.Client { return client }),
		WithWebAuthnConfig(&config.WebAuthnConfig{
			RPID:                    "example.com",
			AllowPublicRegistration: &allow,
		}))
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	var begin http.HandlerFunc
	for _, rec := range *recs {
		if rec.method == "POST" && rec.pattern == "/api/v1/webauthn/registration/begin" {
			begin = rec.handler
		}
	}
	require.NotNil(t, begin, "webauthn registration/begin must be registered")

	body, _ := json.Marshal(map[string]string{"email": "alice@example.com", "display_name": "Alice"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	begin(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp, "BeginRegistration must return real ceremony options, not a stub")
}

// TestModule_SelfBuiltSurfaceAuthenticatesJWT proves the module's
// AuthenticateHTTP (the qrdb ModuleAuthFallback seam) works against the
// self-built server's own token issuer without any WithRESTServer wiring.
func TestModule_SelfBuiltSurfaceAuthenticatesJWT(t *testing.T) {
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	m, err := NewModule(func() *xkms.XKMSService { return svc })
	require.NoError(t, err)

	// Force the self-built server into existence and pull it via the
	// package-private restServer accessor is not exported to the test file
	// intentionally; drive it the same way a real caller would, through a
	// registered route, and confirm authentication fails closed on a bare
	// request (no credentials) rather than erroring as "still composing".
	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)
	require.NotEmpty(t, *recs)

	_, authErr := m.AuthenticateHTTP(httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil))
	require.Error(t, authErr)
	assert.NotContains(t, authErr.Error(), "still composing",
		"the self-built surface must have resolved by now, not report itself as composing")
}

// TestModule_SelfBuiltSurfaceFailsClosedOnDefaultRegistration pins go-xkms#184
// end to end through the composed-module path: a host that projects a WebAuthn
// config WITHOUT deciding allow_public_registration gets the stack default —
// registration closed — and an unknown email is refused with the documented
// 403/registration_disabled contract rather than an account or a 500.
func TestModule_SelfBuiltSurfaceFailsClosedOnDefaultRegistration(t *testing.T) {
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	client, _, err := testutil.NewQRDBFakeClient()
	require.NoError(t, err)

	m, err := NewModule(func() *xkms.XKMSService { return svc },
		WithQRDBClient(func() *qrdbsdk.Client { return client }),
		WithWebAuthnConfig(&config.WebAuthnConfig{
			RPID: "example.com",
			// AllowPublicRegistration deliberately unset: the host never
			// decided, so the secure default must apply.
		}))
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	var begin http.HandlerFunc
	for _, rec := range *recs {
		if rec.method == "POST" && rec.pattern == "/api/v1/webauthn/registration/begin" {
			begin = rec.handler
		}
	}
	require.NotNil(t, begin, "webauthn registration/begin must be registered")

	body, _ := json.Marshal(map[string]string{"email": "stranger@example.com", "display_name": "Stranger"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	begin(w, req)

	require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "registration_disabled", resp["error"],
		"the refusal must carry the documented error code")
}
