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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
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

// newTestTokenIssuerWithResolver builds a token issuer over a fresh
// software ECDSA key, an in-memory refresh store, and the given
// UserResolver, so a test can drive the refresh-time re-check
// (go-xkms#1297) without standing up a qrdb identity plane.
func newTestTokenIssuerWithResolver(t *testing.T, resolver token.UserResolver) *token.Issuer {
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
		UserResolver: resolver,
	})
	require.NoError(t, err)
	return issuer
}

// fakeUserResolver is a scripted token.UserResolver.
type fakeUserResolver struct {
	resolve func(ctx context.Context, id *auth.Identity) (*auth.Identity, error)
}

func (f *fakeUserResolver) ResolveUser(ctx context.Context, id *auth.Identity) (*auth.Identity, error) {
	return f.resolve(ctx, id)
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
		// No attestation anchor: the deployment must say so explicitly, and
		// the token then records that nothing proved a smartcard.
		c.PIVLogin = &PIVLoginOptions{Enabled: true, AllowUnattested: true}
		c.AuthUserStore = &fakeAuthUserStore{user: auth.MTLSUser{
			Username:    "alice",
			DisplayName: "Alice Admin",
			Roles:       []string{"admin"},
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
	assert.Equal(t, PIVAttestLevelUnattested, accessClaims(t, resp.AccessToken)["attest_level"],
		"an accepted login that proved no hardware must say so on the token")
	assert.Equal(t, auth.SubjectKindUsername, accessClaims(t, resp.AccessToken)["sub_kind"],
		"a PIV/mTLS login must declare its subject as a username (go-xkms#1297 review)")
}

func TestPIVLogin_DisabledUserRejected(t *testing.T) {
	server := newAuthTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{Enabled: true, AllowUnattested: true}
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
			Enabled:         true,
			TrustedIssuers:  []string{"CN=Some Other CA"},
			AllowUnattested: true,
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

// TestAuthRefresh_UserResolver_DisabledAccountRefused proves the REST
// refresh endpoint refuses a refresh once the account behind the token is
// disabled, even though the refresh token itself is still valid and
// unrotated (go-xkms#1297).
func TestAuthRefresh_UserResolver_DisabledAccountRefused(t *testing.T) {
	resolver := &fakeUserResolver{
		resolve: func(context.Context, *auth.Identity) (*auth.Identity, error) {
			return nil, auth.ErrUserDisabled
		},
	}
	server := newAuthTestServer(t, func(c *Config) {
		c.TokenIssuer = newTestTokenIssuerWithResolver(t, resolver)
	})

	pair, err := server.tokenIssuer.Mint(context.Background(), &auth.Identity{Subject: "alice"})
	require.NoError(t, err)

	body, err := json.Marshal(authRefreshRequest{RefreshToken: pair.RefreshToken})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))

	w := doAuthRequest(t, server, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

// TestAuthRefresh_UserResolver_DeletedAccountRefused mirrors the disabled
// case for a deleted account: the resolver reports the subject as gone.
func TestAuthRefresh_UserResolver_DeletedAccountRefused(t *testing.T) {
	resolver := &fakeUserResolver{
		resolve: func(context.Context, *auth.Identity) (*auth.Identity, error) {
			return nil, auth.ErrRefreshSubjectNotFound
		},
	}
	server := newAuthTestServer(t, func(c *Config) {
		c.TokenIssuer = newTestTokenIssuerWithResolver(t, resolver)
	})

	pair, err := server.tokenIssuer.Mint(context.Background(), &auth.Identity{Subject: "alice"})
	require.NoError(t, err)

	body, err := json.Marshal(authRefreshRequest{RefreshToken: pair.RefreshToken})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))

	w := doAuthRequest(t, server, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

// TestAuthRefresh_UserResolver_RoleChangeReflected proves a role granted
// after login reaches the very next refreshed access token.
func TestAuthRefresh_UserResolver_RoleChangeReflected(t *testing.T) {
	resolver := &fakeUserResolver{
		resolve: func(_ context.Context, id *auth.Identity) (*auth.Identity, error) {
			fresh := *id
			fresh.Roles = []string{"promoted-role"}
			return &fresh, nil
		},
	}
	server := newAuthTestServer(t, func(c *Config) {
		c.TokenIssuer = newTestTokenIssuerWithResolver(t, resolver)
	})

	pair, err := server.tokenIssuer.Mint(context.Background(), &auth.Identity{Subject: "alice", Roles: []string{"stale-role"}})
	require.NoError(t, err)

	body, err := json.Marshal(authRefreshRequest{RefreshToken: pair.RefreshToken})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))

	w := doAuthRequest(t, server, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp authTokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, []interface{}{"promoted-role"}, accessClaims(t, resp.AccessToken)["roles"])
}

func TestAuthMe_ReturnsIdentityPermissionsCapabilities(t *testing.T) {
	server := newAuthTestServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	w := doAuthRequest(t, server, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp authMeResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Subject)

	// RBAC disabled: every registered permission reads true.
	require.Len(t, resp.Permissions, len(qrdbsdk.AllPermissions()))
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

// authMeAs serves GET /api/v1/auth/me for identity and decodes the response.
func authMeAs(t *testing.T, server *Server, identity *auth.Identity) authMeResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	server.handleAuthMe(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp authMeResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp
}

// TestAuthMe_ReportsBoundAccountUsername covers an identity the qrdb node
// bound to a user account (an mTLS login on the unified listener): the
// username lives in Identity.Username, not in Metadata (#794).
func TestAuthMe_ReportsBoundAccountUsername(t *testing.T) {
	server := newAuthTestServer(t, nil)
	identity := &auth.Identity{
		TenantID: "system",
		Metadata: map[string]string{"auth_method": "mtls"},
	}
	identity.BindUser(42, "admin")

	resp := authMeAs(t, server, identity)
	assert.Equal(t, "admin", resp.Username)
	assert.Equal(t, identity.Subject, resp.Subject)
	assert.Equal(t, "mtls", resp.AuthMethod)
}

// TestAuthMe_UnboundIdentityHasNoUsername covers an identity that resolved to
// no account: no username is invented from its subject.
func TestAuthMe_UnboundIdentityHasNoUsername(t *testing.T) {
	server := newAuthTestServer(t, nil)
	identity := &auth.Identity{
		Subject:  "device-7",
		TenantID: "system",
		Metadata: map[string]string{"auth_method": "mtls"},
	}

	resp := authMeAs(t, server, identity)
	assert.Empty(t, resp.Username)
	assert.Equal(t, "device-7", resp.Subject)
}

// The qrdb node's mTLS authenticator stamps no auth_method, so /auth/me reads
// the method from the client certificate the request presented (#794).
func TestIdentityAuthMethod(t *testing.T) {
	withCert := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	withCert.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	tlsNoCert := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	tlsNoCert.TLS = &tls.ConnectionState{}
	plain := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)

	tests := []struct {
		name     string
		req      *http.Request
		metadata map[string]string
		want     string
	}{
		{"stamped method wins over the certificate", withCert, map[string]string{"auth_method": "jwt"}, "jwt"},
		{"unstamped identity with a client certificate is mtls", withCert, nil, qrdbsdk.MethodMTLS},
		{"unstamped identity over TLS without a certificate", tlsNoCert, nil, ""},
		{"unstamped identity without TLS", plain, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &auth.Identity{Subject: "admin", Metadata: tt.metadata}
			assert.Equal(t, tt.want, identityAuthMethod(tt.req, identity))
		})
	}
}

// TestAuthMe_PermissionsReflectRBACGrant proves /auth/me reports exactly the
// permissions qrdb's RBAC lists for the identity (go-xkms#846, #1557).
func TestAuthMe_PermissionsReflectRBACGrant(t *testing.T) {
	rbac := &recordingRBACClient{allowResource: auth.ResourceUsers, allowAction: auth.ActionList}

	server, err := NewServer(&Config{
		Authenticator:  auth.NewNoOpAuthenticator(),
		Backends:       map[string]xkms.Backend{"test": newMockKeyStore()},
		Logger:         testLogger(),
		TokenIssuer:    newTestTokenIssuer(t),
		EnableRBAC:     true,
		RBACAuthorizer: auth.NewAuthorizer(rbac),
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	w := doAuthRequest(t, server, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp authMeResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.Equal(t, map[string]bool{"users:list": true}, resp.Permissions,
		"/auth/me must report exactly the permissions RBAC lists")
}

// TestAuthMe_PermissionsDenyWithoutRBACGrant is the error-path counterpart:
// an identity whose RBAC grant does not cover users:list must see it as
// false rather than absent or true.
func TestAuthMe_PermissionsDenyWithoutRBACGrant(t *testing.T) {
	// allowResource/allowAction left zero-valued: the identity holds no
	// permission at all.
	rbac := &recordingRBACClient{}

	server, err := NewServer(&Config{
		Authenticator:  auth.NewNoOpAuthenticator(),
		Backends:       map[string]xkms.Backend{"test": newMockKeyStore()},
		Logger:         testLogger(),
		TokenIssuer:    newTestTokenIssuer(t),
		EnableRBAC:     true,
		RBACAuthorizer: auth.NewAuthorizer(rbac),
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	w := doAuthRequest(t, server, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp authMeResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.Empty(t, resp.Permissions, "identity without grants must see no permission")
}

// TestAuthMe_PermissionListErrorFails proves /auth/me fails rather than
// reporting an empty permission set when RBAC cannot list the caller's
// permissions: an empty map would silently hide the whole UI.
func TestAuthMe_PermissionListErrorFails(t *testing.T) {
	rbac := &recordingRBACClient{listErr: errors.New("rbac unavailable")}

	server, err := NewServer(&Config{
		Authenticator:  auth.NewNoOpAuthenticator(),
		Backends:       map[string]xkms.Backend{"test": newMockKeyStore()},
		Logger:         testLogger(),
		TokenIssuer:    newTestTokenIssuer(t),
		EnableRBAC:     true,
		RBACAuthorizer: auth.NewAuthorizer(rbac),
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	w := doAuthRequest(t, server, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
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

// stubLeaderEndpointClient is the smallest xkms.ClusterClient: wiring any
// non-nil client is what marks the service clustered.
type stubLeaderEndpointClient struct{}

func (stubLeaderEndpointClient) LeaderEndpoint(context.Context, uint64, string) (string, error) {
	return "", nil
}

// newCapabilityTestServer builds a server over a fresh XKMSService singleton
// wired with the given cluster client (nil for a standalone node).
func newCapabilityTestServer(t *testing.T, cluster xkms.ClusterClient) *Server {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "mem",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	svc.SetClusterClient(cluster, 1)

	server, err := NewServer(&Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": newMockKeyStore()},
		XKMSService:   svc,
	})
	require.NoError(t, err)
	return server
}

func TestCapabilityFlags_Cluster(t *testing.T) {
	t.Run("clustered", func(t *testing.T) {
		server := newCapabilityTestServer(t, stubLeaderEndpointClient{})
		assert.True(t, server.capabilityFlags()["cluster"])
	})

	t.Run("standalone", func(t *testing.T) {
		server := newCapabilityTestServer(t, nil)
		assert.False(t, server.capabilityFlags()["cluster"])
	})

	t.Run("no xkms service wired", func(t *testing.T) {
		server, err := NewServer(&Config{
			Authenticator: auth.NewNoOpAuthenticator(),
			Backends:      map[string]xkms.Backend{"test": newMockKeyStore()},
		})
		require.NoError(t, err)
		assert.False(t, server.capabilityFlags()["cluster"])
	})
}

func TestCapabilityFlags_TrustRoots(t *testing.T) {
	t.Run("trust root handlers wired", func(t *testing.T) {
		server := &Server{trustRootHandlers: NewTrustRootHandlers(nil)}
		assert.True(t, server.capabilityFlags()["trust_roots"])
	})

	t.Run("no trust root handlers", func(t *testing.T) {
		server, err := NewServer(&Config{
			Authenticator: auth.NewNoOpAuthenticator(),
			Backends:      map[string]xkms.Backend{"test": newMockKeyStore()},
		})
		require.NoError(t, err)
		flags := server.capabilityFlags()
		value, ok := flags["trust_roots"]
		assert.True(t, ok, "trust_roots key must be present")
		assert.False(t, value)
	})
}
