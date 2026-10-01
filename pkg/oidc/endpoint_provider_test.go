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

package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEndpointProvider(t *testing.T) {
	p, err := NewEndpointProvider("https://idp.example.com/", Endpoints{Token: "https://idp.example.com/token"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "https://idp.example.com", p.Issuer)
	assert.True(t, p.HasTokenEndpoint())
	assert.False(t, p.IsInitialized(), "a token-only provider has no authorization endpoint or JWKS")

	_, err = NewEndpointProvider("", Endpoints{Token: "https://idp.example.com/token"}, nil)
	assert.ErrorIs(t, err, ErrInvalidIssuer)
	_, err = NewEndpointProvider("https://idp.example.com", Endpoints{}, nil)
	assert.ErrorIs(t, err, ErrMissingTokenEndpoint)
	_, err = NewEndpointProvider("https://idp.example.com", Endpoints{Token: "http://idp.example.com/token"}, nil)
	assert.ErrorIs(t, err, ErrInsecureEndpoint, "plain http off loopback is refused")

	var nilProvider *Provider
	assert.False(t, nilProvider.HasTokenEndpoint())
}

// TestRefreshWithoutDiscovery proves a token-only provider refreshes: a
// credential imported or device-approved never needs discovery.
func TestRefreshWithoutDiscovery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/token", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "refresh_token", body["grant_type"])
		assert.Equal(t, "rt-1", body["refresh_token"])
		writeJSON(t, w, http.StatusOK, map[string]any{"access_token": "at-2", "refresh_token": "rt-2", "expires_in": 60})
	}))
	defer srv.Close()

	client := deviceTestClient(t, srv, "", TokenEncodingJSON)
	tokens, err := client.Refresh(context.Background(), "rt-1")
	require.NoError(t, err)
	assert.Equal(t, "rt-2", tokens.RefreshToken, "a rotated refresh token is returned")
}

func TestTokenInheritFrom(t *testing.T) {
	prev := &TokenResponse{RefreshToken: "rt", IDToken: "it", Scope: "openid", TokenType: "Bearer", DPoPKeyPEM: "pem"}

	rotated := &TokenResponse{AccessToken: "at2", RefreshToken: "rt2"}
	rotated.InheritFrom(prev)
	assert.Equal(t, "rt2", rotated.RefreshToken, "a rotated refresh token replaces the old one")
	assert.Equal(t, "it", rotated.IDToken)
	assert.Equal(t, "pem", rotated.DPoPKeyPEM)

	kept := &TokenResponse{AccessToken: "at2", IDToken: "it2"}
	kept.InheritFrom(prev)
	assert.Equal(t, "rt", kept.RefreshToken, "an omitted refresh token stays valid")
	assert.Equal(t, "it2", kept.IDToken)

	kept.InheritFrom(nil)
	assert.Equal(t, "rt", kept.RefreshToken)
}

func TestTokenExpiresAt(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, fixed, (&TokenResponse{Expiry: fixed}).ExpiresAt())

	exp := time.Now().Add(time.Hour).Unix()
	jwt := testJWT(t, map[string]any{"exp": exp})
	assert.Equal(t, exp, (&TokenResponse{AccessToken: jwt}).ExpiresAt().Unix())

	assert.True(t, (&TokenResponse{AccessToken: "opaque"}).ExpiresAt().IsZero())
	_, ok := JWTExpiry(testJWT(t, map[string]any{"sub": "x"}))
	assert.False(t, ok)
	_, ok = UnverifiedClaims("a.!!!.c")
	assert.False(t, ok)
}

func TestTemplateFlows(t *testing.T) {
	google, err := GetTemplate("google")
	require.NoError(t, err)
	assert.True(t, google.SupportsFlow(FlowAuthorizationCode), "a pre-existing template keeps the browser login")
	assert.False(t, google.SupportsFlow(FlowImport))

	openai, err := GetTemplate("openai")
	require.NoError(t, err)
	assert.Equal(t, "app_EMoamEEZ73f0CkXaXp7hrann", openai.ClientID)
	assert.Equal(t, "https://auth.openai.com/oauth/token", openai.ResolveTokenEndpoint(""))
	assert.Equal(t, TokenEncodingJSON, openai.TokenEncoding)
	assert.Equal(t, DeviceStyleOpenAI, openai.DeviceStyle)
	assert.True(t, openai.SupportsFlow(FlowDevice))
	assert.True(t, openai.SupportsFlow(FlowImport))
	assert.False(t, openai.SupportsFlow(FlowAuthorizationCode))

	anthropic, err := GetTemplate("anthropic")
	require.NoError(t, err)
	assert.True(t, anthropic.NoRefresh)
	assert.Equal(t, 365*24*time.Hour, anthropic.TokenLifetime)
	assert.Equal(t, []Flow{FlowImport}, anthropic.Flows)
}
