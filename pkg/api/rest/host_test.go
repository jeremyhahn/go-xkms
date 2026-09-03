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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// newFakeQRDBClient builds a real *qrdbsdk.Client around the shared
// in-memory fake transport (pkg/testutil), so these tests exercise
// BuildWebAuthnService / BuildAuthenticator / NewHostServer against a
// working qrdb identity plane instead of hand-waving it.
func newFakeQRDBClient(t *testing.T) (*qrdbsdk.Client, *testutil.QRDBFakeTransport) {
	t.Helper()
	client, ft, err := testutil.NewQRDBFakeClient()
	require.NoError(t, err)
	return client, ft
}

// ---------------------------------------------------------------------------
// BuildTokenIssuer
// ---------------------------------------------------------------------------

func TestBuildTokenIssuer_Success(t *testing.T) {
	backend := xkmsmocks.NewMockKeyStore()
	issuer, err := BuildTokenIssuer(context.Background(), TokenIssuerParams{
		Backend:     backend,
		BackendName: "test",
	})
	require.NoError(t, err)
	require.NotNil(t, issuer)

	// The provisioning path actually generated a key: verify by minting a
	// real token pair and checking it carries the expected subject.
	pair, err := issuer.Mint(context.Background(), &auth.Identity{Subject: "alice"})
	require.NoError(t, err)
	assert.NotEmpty(t, pair.AccessToken)
	assert.NotEmpty(t, pair.RefreshToken)

	// Reusing the same backend/CN must reuse the provisioned key, not
	// generate a second one.
	assert.Len(t, backend.GenerateECDSACalls, 1)
}

func TestBuildTokenIssuer_NilBackend(t *testing.T) {
	_, err := BuildTokenIssuer(context.Background(), TokenIssuerParams{BackendName: "test"})
	require.Error(t, err)
	var backendErr *TokenIssuerBackendError
	require.True(t, errors.As(err, &backendErr))
	assert.ErrorIs(t, err, ErrTokenIssuerBackendRequired)
}

func TestBuildTokenIssuer_RetryPropagatesBackendFailure(t *testing.T) {
	sentinel := errors.New("boom")
	calls := 0
	_, err := BuildTokenIssuer(context.Background(), TokenIssuerParams{
		Backend:     xkmsmocks.NewMockKeyStore(),
		BackendName: "test",
		Retry: func(ctx context.Context, logger *slog.Logger, what string, op func() error) error {
			calls++
			return sentinel
		},
	})
	require.Error(t, err)
	var backendErr *TokenIssuerBackendError
	require.True(t, errors.As(err, &backendErr))
	assert.ErrorIs(t, err, sentinel)
	assert.Equal(t, 1, calls)
}

// ---------------------------------------------------------------------------
// BuildAuthenticator
// ---------------------------------------------------------------------------

func TestBuildAuthenticator_EmptyChain(t *testing.T) {
	_, err := BuildAuthenticator(AuthenticatorParams{})
	require.Error(t, err)
	var buildErr *AuthenticatorBuildError
	require.True(t, errors.As(err, &buildErr))
	assert.ErrorIs(t, err, ErrAuthenticatorChainEmpty)
}

func TestBuildAuthenticator_JWTOnly(t *testing.T) {
	issuer, err := BuildTokenIssuer(context.Background(), TokenIssuerParams{
		Backend:     xkmsmocks.NewMockKeyStore(),
		BackendName: "test",
	})
	require.NoError(t, err)

	authr, err := BuildAuthenticator(AuthenticatorParams{TokenIssuer: issuer})
	require.NoError(t, err)
	require.NotNil(t, authr)
	assert.Equal(t, "jwt", authr.Name())
}

func TestBuildAuthenticator_QRDBOnly(t *testing.T) {
	client, _ := newFakeQRDBClient(t)
	authr, err := BuildAuthenticator(AuthenticatorParams{QRDBClient: client})
	require.NoError(t, err)
	require.NotNil(t, authr)
	assert.Equal(t, "mtls", authr.Name())
}

func TestBuildAuthenticator_Composite(t *testing.T) {
	issuer, err := BuildTokenIssuer(context.Background(), TokenIssuerParams{
		Backend:     xkmsmocks.NewMockKeyStore(),
		BackendName: "test",
	})
	require.NoError(t, err)
	client, _ := newFakeQRDBClient(t)

	authr, err := BuildAuthenticator(AuthenticatorParams{TokenIssuer: issuer, QRDBClient: client})
	require.NoError(t, err)
	require.NotNil(t, authr)
	assert.Equal(t, "composite", authr.Name())
}

// ---------------------------------------------------------------------------
// BuildWebAuthnService
// ---------------------------------------------------------------------------

func TestBuildWebAuthnService_NilConfig(t *testing.T) {
	client, _ := newFakeQRDBClient(t)
	_, err := BuildWebAuthnService(WebAuthnServiceParams{QRDBClient: client})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrWebAuthnConfigRequired)
}

func TestBuildWebAuthnService_NilQRDBClient(t *testing.T) {
	cfg := WebAuthnConfigFromXKMS(&config.WebAuthnConfig{RPID: "example.com"})
	_, err := BuildWebAuthnService(WebAuthnServiceParams{Config: cfg})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrWebAuthnQRDBClientRequired)
}

func TestBuildWebAuthnService_Success(t *testing.T) {
	client, _ := newFakeQRDBClient(t)
	cfg := WebAuthnConfigFromXKMS(&config.WebAuthnConfig{RPID: "example.com"})
	svc, err := BuildWebAuthnService(WebAuthnServiceParams{
		Config:     cfg,
		QRDBClient: client,
		TenantID:   "system",
	})
	require.NoError(t, err)
	require.NotNil(t, svc)
}

// ---------------------------------------------------------------------------
// WebAuthnConfigFromXKMS
// ---------------------------------------------------------------------------

func TestWebAuthnConfigFromXKMS_Defaults(t *testing.T) {
	cfg := WebAuthnConfigFromXKMS(&config.WebAuthnConfig{RPID: "example.com"})
	require.NotNil(t, cfg)
	assert.Equal(t, "example.com", cfg.RPDisplayName, "display name defaults to RPID")
	assert.Equal(t, []string{"https://example.com"}, cfg.RPOrigins, "origin derived from RPID")
}

func TestWebAuthnConfigFromXKMS_Nil(t *testing.T) {
	assert.Nil(t, WebAuthnConfigFromXKMS(nil))
}

// ---------------------------------------------------------------------------
// NewHostServer
// ---------------------------------------------------------------------------

func TestNewHostServer_NilConfig(t *testing.T) {
	_, err := NewHostServer(context.Background(), nil)
	require.Error(t, err)
	var wantErr *HostXKMSServiceRequiredError
	assert.True(t, errors.As(err, &wantErr))
}

func TestNewHostServer_NoBackends(t *testing.T) {
	// Zero-value XKMSService: no backends, no default backend -- exactly
	// the "host gave nothing usable" construction failure the qrdb
	// ServiceModule's self-build path (pkg/apimodule) surfaces as a loud
	// 503 rather than silently registering nothing.
	_, err := NewHostServer(context.Background(), &HostConfig{XKMSService: &xkms.XKMSService{}})
	require.Error(t, err)
}

func TestNewHostServer_MinimalSuccess(t *testing.T) {
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	srv, err := NewHostServer(context.Background(), &HostConfig{XKMSService: svc})
	require.NoError(t, err)
	require.NotNil(t, srv)

	// No qrdb client / webauthn config given: the login-plane routes stay
	// unmounted, but the base surface is a real, serving *Server (e.g.
	// /health, a public route with no dependency on the login plane).
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestNewHostServer_WebAuthnServesRealCeremony proves a host that supplies a
// qrdb client and a WebAuthn config gets a WORKING WebAuthn ceremony surface
// -- a real 200 from BeginRegistration -- not a 404 (route never registered)
// or 401 (default-deny), which is exactly the composition bug this
// construction path fixes for a host embedding the qrdb ServiceModule.
func TestNewHostServer_WebAuthnServesRealCeremony(t *testing.T) {
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	client, _ := newFakeQRDBClient(t)

	allow := true
	waCfg := WebAuthnConfigFromXKMS(&config.WebAuthnConfig{
		RPID:                    "example.com",
		AllowPublicRegistration: &allow,
	})

	srv, err := NewHostServer(context.Background(), &HostConfig{
		XKMSService: svc,
		QRDBClient:  client,
		WebAuthn:    waCfg,
	})
	require.NoError(t, err)
	require.NotNil(t, srv)

	body, _ := json.Marshal(map[string]string{"email": "alice@example.com", "display_name": "Alice"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp, "BeginRegistration must return real ceremony options")
}

// TestNewHostServer_AuthenticateHTTP proves a host-built server's
// AuthenticateHTTP verifies a JWT minted by its own self-built token
// issuer -- the same seam pkg/apimodule's ModuleAuthFallback consults.
func TestNewHostServer_AuthenticateHTTP(t *testing.T) {
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	srv, err := NewHostServer(context.Background(), &HostConfig{XKMSService: svc})
	require.NoError(t, err)

	// No token issuer was mintable without a qrdb client's refresh store?
	// BuildTokenIssuer falls back to an in-memory refresh store when
	// QRDBClient is nil, so the issuer is still built here.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	_, authErr := srv.AuthenticateHTTP(req)
	require.Error(t, authErr, "a request with no credentials must fail authentication")
}

// TestWebAuthnConfigFromXKMS_RegistrationPolicyPassThrough pins the
// subordination contract from go-xkms#184: the projection a composing host
// (go-quicbaas's WithServiceModuleWebAuthn) feeds through this function
// carries the host's registration decision verbatim — explicit values in
// both directions, and nil untouched so the secure default (closed) applies.
// Two flags disagreeing about whether an anonymous user may register is the
// failure mode this pass-through designs away.
func TestWebAuthnConfigFromXKMS_RegistrationPolicyPassThrough(t *testing.T) {
	open, closed := true, false

	tests := []struct {
		name      string
		in        *bool
		wantNil   bool
		wantAllow bool
	}{
		{"unset stays unset and reads closed", nil, true, false},
		{"explicit true stays true", &open, false, true},
		{"explicit false stays false", &closed, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WebAuthnConfigFromXKMS(&config.WebAuthnConfig{
				RPID:                    "example.com",
				AllowPublicRegistration: tt.in,
			})
			require.NotNil(t, got)
			if tt.wantNil {
				assert.Nil(t, got.AllowPublicRegistration,
					"projection must not invent a value the host never set")
			} else {
				require.NotNil(t, got.AllowPublicRegistration)
				assert.Equal(t, *tt.in, *got.AllowPublicRegistration,
					"projection must carry the host's decision verbatim")
			}
			assert.Equal(t, tt.wantAllow, got.PublicRegistrationAllowed())
		})
	}
}
