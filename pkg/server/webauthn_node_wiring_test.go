// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// publicRouteWiring builds xkmsd over an embedded go-qrdb node that enforces
// authentication, with WebAuthn and PIV login on, and returns the REST
// handler plus an administrator access token from a PIV login.
func publicRouteWiring(t *testing.T) (do func(*http.Request) *httptest.ResponseRecorder, adminToken string) {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	openRegistration := true
	cfg := qrdbBarrierConfig(t)
	cfg.Barrier = config.BarrierConfig{Enabled: true, Strategy: "none"}
	cfg.Auth.Type = "composite"
	if cfg.Auth.JWT != nil {
		cfg.Auth.JWT.PublicKeyFile = ""
	}
	cfg.TLS.ClientAuth = "request"
	cfg.TLS.ServerCN = "localhost"
	cfg.Auth.PIVLogin = &config.PIVLoginConfig{Enabled: true, AllowUnattested: true}
	cfg.WebAuthn = &config.WebAuthnConfig{
		Enabled:       true,
		RPID:          "localhost",
		RPDisplayName: "Test",
		RPOrigins:     []string{"https://localhost"},
		// Open sign-up, so registration/begin for a new email reaches the
		// user lookup and answers 200 rather than the invite-only refusal.
		AllowPublicRegistration: &openRegistration,
	}

	s, err := New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Shutdown() })
	require.NotNil(t, s.qrdbNode, "the wiring under test is the embedded node")
	require.NotNil(t, s.webauthnService, "WebAuthn must be built on the node")

	restCfg, err := s.buildRESTConfig()
	require.NoError(t, err)
	srv, err := rest.NewServer(restCfg)
	require.NoError(t, err)
	h := srv.Handler()
	do = func(req *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	cert := loadFirstBootAdminCert(t, cfg.Datastore.Path)
	login := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/piv", nil)
	login.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := do(login)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var pair loginWiringTokens
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pair))
	require.NotEmpty(t, pair.AccessToken)
	return do, pair.AccessToken
}

func jsonRequest(t *testing.T, method, path string, payload any) *http.Request {
	t.Helper()
	raw := []byte("{}")
	if payload != nil {
		var err error
		raw, err = json.Marshal(payload)
		require.NoError(t, err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// TestPublicRouteWiring_WebAuthnBeginOverAuthNode is ruling 973 (1): at
// ef2e3435d both ceremonies' begin answered 500 "webauthn begin
// registration: get user by email: qrdb user lookup: qrdb/auth:
// unauthenticated", because the WebAuthn user store looked users up through
// the datastore client with the anonymous request context.
func TestPublicRouteWiring_WebAuthnBeginOverAuthNode(t *testing.T) {
	do, _ := publicRouteWiring(t)

	const email = "passkey-user@example.com"
	w := do(jsonRequest(t, http.MethodPost, "/api/v1/webauthn/registration/begin", map[string]string{
		"email":        email,
		"display_name": "Passkey User",
	}))
	require.Equal(t, http.StatusOK, w.Code, "registration/begin: %s", w.Body.String())

	w = do(jsonRequest(t, http.MethodPost, "/api/v1/webauthn/login/begin", map[string]string{"email": email}))
	require.NotEqual(t, http.StatusInternalServerError, w.Code, "login/begin: %s", w.Body.String())
	require.NotContains(t, w.Body.String(), "unauthenticated")
}

// TestPublicRouteWiring_FreshInviteRedeems_NotUnauthenticatedAsUnusable is
// ruling 973 (2): at ef2e3435d a freshly issued invite answered 404 "link is
// not valid" because GetInvite's GetUser ran through the datastore client
// with the anonymous request context, failed with qrdb/auth:
// unauthenticated, and servicer_invite.go mapped that to ErrInviteUnusable.
func TestPublicRouteWiring_FreshInviteRedeems_NotUnauthenticatedAsUnusable(t *testing.T) {
	do, admin := publicRouteWiring(t)

	req := jsonRequest(t, http.MethodPost, "/api/v1/users", map[string]any{
		"username":     "invitee",
		"email":        "invitee@example.com",
		"display_name": "Invitee",
	})
	req.Header.Set("Authorization", "Bearer "+admin)
	w := do(req)
	require.Contains(t, []int{http.StatusOK, http.StatusCreated}, w.Code, "create user: %s", w.Body.String())
	var created struct {
		Invite struct {
			Token string `json:"token"`
			URL   string `json:"url"`
		} `json:"invite"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created), w.Body.String())
	token := created.Invite.Token
	if token == "" {
		token = created.Invite.URL[strings.LastIndex(created.Invite.URL, "/")+1:]
	}
	require.NotEmpty(t, token, "create user must issue an invite: %s", w.Body.String())

	w = do(httptest.NewRequest(http.MethodGet, "/api/v1/invites/"+qrdbsdk.SystemTenantID+"/"+token, nil))
	require.Equal(t, http.StatusOK, w.Code, "fresh invite lookup: %s", w.Body.String())

	w = do(jsonRequest(t, http.MethodPost, "/api/v1/invites/"+qrdbsdk.SystemTenantID+"/"+token+"/fido2/begin", nil))
	require.Equal(t, http.StatusOK, w.Code, "fresh invite fido2/begin: %s", w.Body.String())
}
