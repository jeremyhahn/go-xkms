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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
)

// newSessionAuthServer wires the session-token plane the way a host does:
// the certificate login mints through the issuer, and bearer requests
// authenticate through a JWT authenticator over the issuer's public key. This
// is the path a browser or agent takes between logging in and asking
// /auth/me who it is, so the identity survives a real claim round trip.
func newSessionAuthServer(t *testing.T, user auth.MTLSUser) (*Server, *token.Issuer) {
	t.Helper()

	issuer := newTestTokenIssuer(t)
	jwtAuth, err := auth.NewJWTAuthenticator(&auth.JWTConfig{
		PublicKey:  issuer.PublicKey(),
		Issuer:     issuer.IssuerName(),
		Audience:   issuer.Audience(),
		HeaderName: "Authorization",
	})
	require.NoError(t, err)

	server := newAuthTestServer(t, func(c *Config) {
		c.TokenIssuer = issuer
		c.Authenticator = jwtAuth
		c.PIVLogin = &PIVLoginOptions{Enabled: true}
		c.AuthUserStore = &fakeAuthUserStore{user: user}
	})
	return server, issuer
}

// pivLoginPair performs the certificate login and returns the minted pair.
func pivLoginPair(t *testing.T, server *Server) authTokenResponse {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, key)

	w := doAuthRequest(t, server, pivRequest(cert))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var pair authTokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pair))
	return pair
}

// authMeBody fetches /auth/me as a raw object so tests can distinguish an
// absent key from an empty one — the contract is absence, not "".
func authMeBody(t *testing.T, server *Server, accessToken string) map[string]json.RawMessage {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	w := doAuthRequest(t, server, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body
}

func rawString(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var s string
	require.NoError(t, json.Unmarshal(raw, &s))
	return s
}

// TestAuthMe_EmailRoundTripsFromCertificateLogin proves go-xkms#194: the
// canonical email login key established at login reaches the caller of
// /auth/me, through the access token and again through a rotated pair.
func TestAuthMe_EmailRoundTripsFromCertificateLogin(t *testing.T) {
	server, _ := newSessionAuthServer(t, auth.MTLSUser{
		Username:    "alice",
		Email:       "alice@example.com",
		DisplayName: "Alice Admin",
		Role:        "admin",
		TenantID:    "system",
		Enabled:     true,
	})

	pair := pivLoginPair(t, server)

	body := authMeBody(t, server, pair.AccessToken)
	require.Contains(t, body, "email", "the login key must be returned: %s", body)
	assert.Equal(t, "alice@example.com", rawString(t, body["email"]))
	assert.Equal(t, "alice", rawString(t, body["username"]))
	assert.Equal(t, "Alice Admin", rawString(t, body["display_name"]))
	// auth_method describes how *this* request authenticated, not the
	// ceremony that minted the token: the bearer request is a JWT one. The
	// login key is what has to survive the hop, and it does.
	assert.Equal(t, "jwt", rawString(t, body["auth_method"]))

	// A refresh rebuilds the identity from the refresh-token snapshot; the
	// login key must survive that rebuild too.
	refreshBody, err := json.Marshal(authRefreshRequest{RefreshToken: pair.RefreshToken})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(refreshBody))
	w := doAuthRequest(t, server, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var rotated authTokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rotated))

	body = authMeBody(t, server, rotated.AccessToken)
	require.Contains(t, body, "email", "the login key must survive refresh: %s", body)
	assert.Equal(t, "alice@example.com", rawString(t, body["email"]))
}

// TestAuthMe_OmitsEmailForPrincipalWithoutOne proves a principal that has no
// email login key — a service or bootstrap account bound only by certificate
// — yields an absent field, never a value fabricated from the username.
func TestAuthMe_OmitsEmailForPrincipalWithoutOne(t *testing.T) {
	server, _ := newSessionAuthServer(t, auth.MTLSUser{
		Username: "svc-backup",
		Role:     "operator",
		TenantID: "system",
		Enabled:  true,
	})

	pair := pivLoginPair(t, server)

	body := authMeBody(t, server, pair.AccessToken)
	assert.Equal(t, "svc-backup", rawString(t, body["username"]))
	_, present := body["email"]
	assert.False(t, present, "a principal without a login key must not get one invented: %s", body)
}

// TestAuthMe_AnonymousIdentityHasNoEmail covers the no-op authenticator: an
// identity with no metadata beyond its method carries no email.
func TestAuthMe_AnonymousIdentityHasNoEmail(t *testing.T) {
	server := newAuthTestServer(t, nil)

	body := authMeBody(t, server, "")
	_, present := body["email"]
	assert.False(t, present, "anonymous identity must not carry an email: %s", body)
}
