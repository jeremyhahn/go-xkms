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

package services

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loginWithDPoP runs a standard OIDC login against a local provider whose
// token endpoint records whether the exchange carried a DPoP proof, with the
// provider's DPoP opt-in set to dpop.
func loginWithDPoP(t *testing.T, dpop bool) (result *OIDCLoginResult, sawProof bool, saved string) {
	t.Helper()

	var proofSeen atomic.Bool
	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 serverURL,
			"authorization_endpoint": serverURL + "/authorize",
			"token_endpoint":         serverURL + "/token",
			"jwks_uri":               serverURL + "/jwks",
		}))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		proofSeen.Store(r.Header.Get("DPoP") != "")
		tokenType := "Bearer"
		if proofSeen.Load() {
			tokenType = "DPoP"
		}
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "dpop-access-token",
			"token_type":   tokenType,
			"expires_in":   3600,
		}))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	serverURL = server.URL

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())
	redirect := "http://127.0.0.1:" + strconv.Itoa(port) + "/callback"

	svc := NewOIDCService(nil)
	svc.SetContext(context.Background())
	store := newTestOIDCTokenStore(t)
	svc.SetTokenStore(store)
	svc.SetBrowserOpen(func(authURL string) error {
		u, parseErr := url.Parse(authURL)
		if !assert.NoError(t, parseErr) {
			return parseErr
		}
		resp, getErr := http.Get(redirect + "?code=dpop-code&state=" + //nolint:noctx // fixed test-local callback URL
			url.QueryEscape(u.Query().Get("state")))
		if assert.NoError(t, getErr) {
			assert.NoError(t, resp.Body.Close())
		}
		return nil
	})

	require.NoError(t, svc.AddProvider(&OIDCProviderEntry{
		Name:        "dpop-provider",
		Issuer:      serverURL,
		ClientID:    "test-client",
		RedirectURL: redirect,
		Scopes:      []string{"openid"},
		DPoP:        dpop,
	}))

	result, err = svc.Login("dpop-provider")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Success, "login error: %s", result.Error)

	tokens, err := store.Load(serverURL)
	require.NoError(t, err)
	return result, proofSeen.Load(), tokens.DPoPKeyPEM
}

// TestOIDCService_Login_DPoPBindsAndPersistsTheKey checks the opt-in: the
// token exchange carries a DPoP proof, and the proof key is saved with the
// tokens so a later refresh can present the same key.
func TestOIDCService_Login_DPoPBindsAndPersistsTheKey(t *testing.T) {
	result, sawProof, savedKey := loginWithDPoP(t, true)

	assert.True(t, sawProof, "the token request must carry a DPoP proof")
	assert.True(t, result.Token.HasDPoP)
	assert.Contains(t, savedKey, "PRIVATE KEY", "the proof key must be persisted with the tokens")
}

// TestOIDCService_Login_DPoPIsNeverImplied checks the other half of the
// opt-in: without it, no proof is sent and no key is stored.
func TestOIDCService_Login_DPoPIsNeverImplied(t *testing.T) {
	result, sawProof, savedKey := loginWithDPoP(t, false)

	assert.False(t, sawProof, "DPoP must not be enabled without the user's opt-in")
	assert.False(t, result.Token.HasDPoP)
	assert.Empty(t, savedKey)
}
