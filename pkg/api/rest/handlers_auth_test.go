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

package rest

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newTestTokenIssuer builds a token issuer over a fresh software ECDSA key
// and an in-memory refresh store.
func newTestTokenIssuer(t *testing.T) *token.Issuer {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer, err := token.NewIssuer(&token.Config{
		Signer: key,
		KeyAttributes: &types.KeyAttributes{
			KeyAlgorithm:       x509.ECDSA,
			SignatureAlgorithm: x509.ECDSAWithSHA256,
			Hash:               stdcrypto.SHA256,
		},
		RefreshStore: token.NewMemoryRefreshStore(),
	})
	require.NoError(t, err)
	return issuer
}

// fakeAuthUserStore maps every fingerprint to one configured user.
type fakeAuthUserStore struct {
	user auth.MTLSUser
	err  error
}

func (f *fakeAuthUserStore) GetByCertFingerprint(_ context.Context, _ string) (auth.MTLSUser, error) {
	return f.user, f.err
}

// newAuthTestServer builds a REST server with the session-token plane wired.
func newAuthTestServer(t *testing.T, mutate func(*Config)) *Server {
	t.Helper()

	cfg := &Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": newMockKeyStore()},
		Logger:        testLogger(),
		TokenIssuer:   newTestTokenIssuer(t),
	}
	if mutate != nil {
		mutate(cfg)
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	return server
}

// doAuthRequest runs a request through the full router.
func doAuthRequest(t *testing.T, s *Server, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)
	return w
}

// pivRequest builds a cert-login request carrying the given peer certificate.
func pivRequest(cert *x509.Certificate) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/piv", nil)
	if cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	return req
}

func TestPIVLogin_DisabledByDefault(t *testing.T) {
	server := newAuthTestServer(t, nil)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, key)

	w := doAuthRequest(t, server, pivRequest(cert))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPIVLogin_RequiresClientCertificate(t *testing.T) {
	server := newAuthTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{Enabled: true}
		c.AuthUserStore = &fakeAuthUserStore{user: auth.MTLSUser{Username: "alice", Enabled: true}}
	})

	w := doAuthRequest(t, server, pivRequest(nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPIVLogin_Success(t *testing.T) {
	server := newAuthTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{Enabled: true}
		c.AuthUserStore = &fakeAuthUserStore{user: auth.MTLSUser{
			Username:    "alice",
			DisplayName: "Alice Admin",
			Role:        "admin",
			TenantID:    "system",
			Enabled:     true,
		}}
	})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, key)

	w := doAuthRequest(t, server, pivRequest(cert))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp authTokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Positive(t, resp.ExpiresIn)
}

func TestPIVLogin_DisabledUserRejected(t *testing.T) {
	server := newAuthTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{Enabled: true}
		c.AuthUserStore = &fakeAuthUserStore{user: auth.MTLSUser{Username: "mallory", Enabled: false}}
	})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, key)

	w := doAuthRequest(t, server, pivRequest(cert))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPIVLogin_UntrustedIssuerRejected(t *testing.T) {
	server := newAuthTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{
			Enabled:        true,
			TrustedIssuers: []string{"CN=Some Other CA"},
		}
		c.AuthUserStore = &fakeAuthUserStore{user: auth.MTLSUser{Username: "alice", Enabled: true}}
	})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, key)

	w := doAuthRequest(t, server, pivRequest(cert))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthRefresh_RotatesPair(t *testing.T) {
	server := newAuthTestServer(t, nil)

	pair, err := server.tokenIssuer.Mint(context.Background(), &auth.Identity{Subject: "alice"})
	require.NoError(t, err)

	body, err := json.Marshal(authRefreshRequest{RefreshToken: pair.RefreshToken})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))

	w := doAuthRequest(t, server, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp authTokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEqual(t, pair.RefreshToken, resp.RefreshToken)
}

func TestAuthRefresh_InvalidToken(t *testing.T) {
	server := newAuthTestServer(t, nil)

	for _, body := range []string{`{}`, `{"refresh_token":"garbage"}`, `not-json`} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader([]byte(body)))
		w := doAuthRequest(t, server, req)
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusUnauthorized}, w.Code, "body %q", body)
	}
}

func TestAuthRefresh_ReuseRevokesFamily(t *testing.T) {
	server := newAuthTestServer(t, nil)

	pair, err := server.tokenIssuer.Mint(context.Background(), &auth.Identity{Subject: "alice"})
	require.NoError(t, err)

	send := func(refresh string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(authRefreshRequest{RefreshToken: refresh})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
		return doAuthRequest(t, server, req)
	}

	first := send(pair.RefreshToken)
	require.Equal(t, http.StatusOK, first.Code)

	var rotated authTokenResponse
	require.NoError(t, json.Unmarshal(first.Body.Bytes(), &rotated))

	// Replay of the rotated token fails and kills the successor too.
	assert.Equal(t, http.StatusUnauthorized, send(pair.RefreshToken).Code)
	assert.Equal(t, http.StatusUnauthorized, send(rotated.RefreshToken).Code)
}

func TestAuthMe_ReturnsIdentityPermissionsCapabilities(t *testing.T) {
	server := newAuthTestServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	w := doAuthRequest(t, server, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp authMeResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Subject)

	// RBAC disabled: every UI permission reads true.
	require.NotEmpty(t, resp.Permissions)
	for key, allowed := range resp.Permissions {
		assert.True(t, allowed, "permission %s should be true without RBAC", key)
	}

	// Capability flags reflect this minimal deployment: no CA, no RBAC, no
	// WebAuthn, no SSH client wired.
	require.NotEmpty(t, resp.Capabilities)
	assert.False(t, resp.Capabilities["ca"])
	assert.False(t, resp.Capabilities["rbac"])
	assert.False(t, resp.Capabilities["webauthn"])
	assert.False(t, resp.Capabilities["ssh"])
}

func TestAuthValidate_ReturnsSubject(t *testing.T) {
	server := newAuthTestServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/validate", nil)
	w := doAuthRequest(t, server, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resp authValidateResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Subject)
}

func TestAuthLogout_IdempotentAndRevokes(t *testing.T) {
	server := newAuthTestServer(t, nil)

	pair, err := server.tokenIssuer.Mint(context.Background(), &auth.Identity{Subject: "alice"})
	require.NoError(t, err)

	logout := func(refresh string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(authRefreshRequest{RefreshToken: refresh})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewReader(body))
		return doAuthRequest(t, server, req)
	}

	assert.Equal(t, http.StatusNoContent, logout(pair.RefreshToken).Code)

	// The revoked token can no longer refresh.
	body, _ := json.Marshal(authRefreshRequest{RefreshToken: pair.RefreshToken})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
	assert.Equal(t, http.StatusUnauthorized, doAuthRequest(t, server, req).Code)

	// Logout is idempotent, even with garbage.
	assert.Equal(t, http.StatusNoContent, logout(pair.RefreshToken).Code)
	assert.Equal(t, http.StatusNoContent, logout("garbage").Code)
}

func TestAuthRoutes_AbsentWithoutIssuer(t *testing.T) {
	cfg := &Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": newMockKeyStore()},
		Logger:        testLogger(),
	}
	server, err := NewServer(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	w := doAuthRequest(t, server, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
