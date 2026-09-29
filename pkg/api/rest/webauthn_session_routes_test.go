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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	webauthnhttp "github.com/jeremyhahn/go-xkms/pkg/webauthn/http"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// webauthnSessionFixture is a REST server whose WebAuthn relying party mints
// real session tokens and whose authenticator verifies them, so the
// session-authenticated WebAuthn routes run exactly as in production.
type webauthnSessionFixture struct {
	server *Server
	svc    *webauthn.Service
}

func newWebAuthnSessionFixture(t *testing.T) *webauthnSessionFixture {
	t.Helper()
	issuer := newTestTokenIssuer(t)
	client, _ := newFakeQRDBClient(t)
	cfg := qrdbWebAuthnConfig()

	svc, err := BuildWebAuthnService(WebAuthnServiceParams{Config: cfg, QRDBClient: client, TokenIssuer: issuer})
	require.NoError(t, err)
	authenticator, err := BuildAuthenticator(AuthenticatorParams{TokenIssuer: issuer})
	require.NoError(t, err)

	server, err := NewServer(&Config{
		Authenticator:   authenticator,
		Backends:        map[string]xkms.Backend{"test": newMockKeyStore()},
		Logger:          testLogger(),
		TokenIssuer:     issuer,
		WebAuthnConfig:  cfg,
		WebAuthnService: svc,
	})
	require.NoError(t, err)
	return &webauthnSessionFixture{server: server, svc: svc}
}

// enroll registers a first passkey for email and returns the account and the
// session token the ceremony minted.
func (f *webauthnSessionFixture) enroll(t *testing.T, email string) (webauthn.User, string) {
	t.Helper()
	ctx := context.Background()
	options, sessionID, err := f.svc.BeginRegistration(ctx, email, email)
	require.NoError(t, err)
	user, err := f.svc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	token := f.attest(t, options.Response.Challenge, user.WebAuthnID(), sessionID)
	return user, token
}

// attest completes a registration ceremony with a fresh mock authenticator.
func (f *webauthnSessionFixture) attest(t *testing.T, challenge []byte, handle []byte, sessionID string) string {
	t.Helper()
	authenticator, err := webauthn.NewMockAuthenticator("example.com")
	require.NoError(t, err)
	attestation, err := authenticator.CreateAttestationObject(challenge, handle, "https://example.com")
	require.NoError(t, err)
	token, _, err := f.svc.FinishRegistration(context.Background(), sessionID, attestation)
	require.NoError(t, err)
	return token
}

func (f *webauthnSessionFixture) do(method, path, token string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.server.server.Handler.ServeHTTP(w, req)
	return w
}

// creationOptions decodes a begin-registration response.
type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		User      struct {
			ID string `json:"id"`
		} `json:"user"`
		ExcludeCredentials []json.RawMessage `json:"excludeCredentials"`
	} `json:"publicKey"`
}

// TestWebAuthnAddCredential_RequiresSession is go-xkms#1294 through the full
// router: the add-passkey route is served only to an authenticated session.
func TestWebAuthnAddCredential_RequiresSession(t *testing.T) {
	f := newWebAuthnSessionFixture(t)

	w := f.do(http.MethodPost, "/api/v1/webauthn/credentials/begin", "", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	w = f.do(http.MethodPost, "/api/v1/webauthn/credentials/begin", "not-a-token", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

// TestWebAuthnAddCredential_OwnSessionAddsPasskey proves the account's own
// session adds a second passkey, while the public ceremony refuses it.
func TestWebAuthnAddCredential_OwnSessionAddsPasskey(t *testing.T) {
	f := newWebAuthnSessionFixture(t)
	alice, token := f.enroll(t, "alice@example.com")

	public, _ := json.Marshal(map[string]string{"email": "alice@example.com"})
	w := f.do(http.MethodPost, "/api/v1/webauthn/registration/begin", "", public)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	var refusal ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &refusal))
	assert.Equal(t, webauthnhttp.ErrorCodeRegistrationRefused, refusal.Error)

	w = f.do(http.MethodPost, "/api/v1/webauthn/credentials/begin", token, nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	sessionID := w.Header().Get(webauthnhttp.HeaderSessionID)
	require.NotEmpty(t, sessionID)

	var options creationOptions
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &options))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(alice.WebAuthnID()), options.PublicKey.User.ID)
	assert.Len(t, options.PublicKey.ExcludeCredentials, 1)

	challenge, err := base64.RawURLEncoding.DecodeString(options.PublicKey.Challenge)
	require.NoError(t, err)
	f.attest(t, challenge, alice.WebAuthnID(), sessionID)

	creds, err := f.svc.GetCredentials(context.Background(), alice.WebAuthnID())
	require.NoError(t, err)
	assert.Len(t, creds, 2)
}

// TestWebAuthnAddCredential_OtherSessionCannotAdd proves another user's
// session only ever reaches its own account.
func TestWebAuthnAddCredential_OtherSessionCannotAdd(t *testing.T) {
	f := newWebAuthnSessionFixture(t)
	alice, _ := f.enroll(t, "alice@example.com")
	bob, bobToken := f.enroll(t, "bob@example.com")

	// The body cannot redirect the ceremony: the account comes from the
	// session alone.
	body, _ := json.Marshal(map[string]string{"email": "alice@example.com"})
	w := f.do(http.MethodPost, "/api/v1/webauthn/credentials/begin", bobToken, body)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var options creationOptions
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &options))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(bob.WebAuthnID()), options.PublicKey.User.ID)

	creds, err := f.svc.GetCredentials(context.Background(), alice.WebAuthnID())
	require.NoError(t, err)
	assert.Len(t, creds, 1, "bob's session must not touch alice's account")
}

// TestWebAuthnRegistrationStatus_Removed pins the go-xkms#1296 removal of the
// unauthenticated registration-status probe.
func TestWebAuthnRegistrationStatus_Removed(t *testing.T) {
	f := newWebAuthnSessionFixture(t)
	f.enroll(t, "alice@example.com")

	w := f.do(http.MethodGet, "/api/v1/webauthn/registration/status?email=alice@example.com", "", nil)
	assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, w.Code)
	assert.NotContains(t, w.Body.String(), "registered")
}

// TestWebAuthnBeginLogin_NoUserIDHeader pins that login/begin answers a known
// and an unknown email alike, with no X-User-Id.
func TestWebAuthnBeginLogin_NoUserIDHeader(t *testing.T) {
	f := newWebAuthnSessionFixture(t)
	f.enroll(t, "alice@example.com")

	for _, email := range []string{"alice@example.com", "nobody@example.com"} {
		body, _ := json.Marshal(map[string]string{"email": email})
		w := f.do(http.MethodPost, "/api/v1/webauthn/login/begin", "", body)
		assert.Equal(t, http.StatusOK, w.Code, email)
		assert.NotEmpty(t, w.Header().Get(webauthnhttp.HeaderSessionID), email)
		assert.Empty(t, w.Header().Get("X-User-Id"), email)
	}
}
