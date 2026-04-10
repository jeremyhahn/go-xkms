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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestProvider creates a Provider pre-populated with endpoints pointing at
// the given httptest server URL. The provider is fully initialized (has
// authorization, token, userinfo, jwks, and revocation endpoints set) so that
// Client methods do not return ErrProviderNotInitialized.
func newTestProvider(serverURL string) *Provider {
	return &Provider{
		Issuer:                serverURL,
		AuthorizationEndpoint: serverURL + "/authorize",
		TokenEndpoint:         serverURL + "/token",
		UserinfoEndpoint:      serverURL + "/userinfo",
		JwksURI:               serverURL + "/jwks",
		RevocationEndpoint:    serverURL + "/revoke",
		jwksCache:             &JWKSCache{},
	}
}

// newTestConfig creates a ProviderConfig suitable for use with the test server.
func newTestConfig(serverURL string) *ProviderConfig {
	return &ProviderConfig{
		Issuer:      serverURL,
		ClientID:    "test-client",
		RedirectURL: "http://localhost:8085/callback",
		Scopes:      []string{"openid", "profile", "email", "offline_access"},
	}
}

// parseDPoPHeader is a test helper that decodes the header and payload sections
// of a DPoP proof JWT without verifying the signature. It returns the decoded
// header and payload as generic maps. This is sufficient for mock server
// validation because the server only needs to check structural correctness.
func parseDPoPHeader(t *testing.T, proof string) (header, payload map[string]interface{}) {
	t.Helper()

	parts := strings.Split(proof, ".")
	require.Len(t, parts, 3, "DPoP proof must have 3 JWT segments")

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err, "failed to base64-decode DPoP header")
	require.NoError(t, json.Unmarshal(headerJSON, &header), "failed to unmarshal DPoP header")

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err, "failed to base64-decode DPoP payload")
	require.NoError(t, json.Unmarshal(payloadJSON, &payload), "failed to unmarshal DPoP payload")

	return header, payload
}

// writeTokenResponse is a test helper that writes a standard OAuth2 token
// response JSON body with the given access token, token type, and refresh token.
func writeTokenResponse(t *testing.T, w http.ResponseWriter, accessToken, tokenType, refreshToken string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    tokenType,
		"refresh_token": refreshToken,
		"expires_in":    3600,
		"scope":         "openid profile email offline_access",
	})
	require.NoError(t, err)
}

func TestClient_DPoPTokenExchange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify HTTP method
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// The DPoP header must be present when the client has a DPoP key.
		dpopProof := r.Header.Get("DPoP")
		if dpopProof == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_dpop_proof",
				"error_description": "missing DPoP header",
			})
			return
		}

		// Parse and validate DPoP JWT structure.
		header, payload := parseDPoPHeader(t, dpopProof)

		// RFC 9449: typ MUST be "dpop+jwt"
		assert.Equal(t, "dpop+jwt", header["typ"], "DPoP JWT typ must be dpop+jwt")
		// RFC 9449: alg MUST be ES256 for our implementation
		assert.Equal(t, "ES256", header["alg"], "DPoP JWT alg must be ES256")
		// JWK must be embedded in the header
		jwk, ok := header["jwk"].(map[string]interface{})
		assert.True(t, ok, "DPoP JWT header must contain jwk")
		assert.Equal(t, "EC", jwk["kty"])
		assert.Equal(t, "P-256", jwk["crv"])
		assert.NotEmpty(t, jwk["x"])
		assert.NotEmpty(t, jwk["y"])

		// Payload must contain htm and htu
		assert.Equal(t, "POST", payload["htm"])
		assert.NotEmpty(t, payload["htu"])
		assert.NotEmpty(t, payload["jti"])
		assert.NotNil(t, payload["iat"])

		writeTokenResponse(t, w, "dpop-access-token", "DPoP", "dpop-refresh-token")
	}))
	defer server.Close()

	provider := newTestProvider(server.URL)
	config := newTestConfig(server.URL)
	client := NewClient(provider, config)

	dpopKey, err := GenerateDPoPKey()
	require.NoError(t, err)
	client.SetDPoPKey(dpopKey)

	pkce, err := GeneratePKCEParams()
	require.NoError(t, err)

	state, err := GenerateState()
	require.NoError(t, err)

	opts := &AuthCodeOptions{
		State:        state,
		CodeVerifier: pkce.CodeVerifier,
	}

	ctx := context.Background()
	tokens, err := client.Exchange(ctx, "valid-auth-code", opts)
	require.NoError(t, err)
	assert.Equal(t, "dpop-access-token", tokens.AccessToken)
	assert.Equal(t, "DPoP", tokens.TokenType)
	assert.Equal(t, "dpop-refresh-token", tokens.RefreshToken)
}

func TestClient_DPoPNonceRetry(t *testing.T) {
	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := requestCount.Add(1)

		dpopProof := r.Header.Get("DPoP")
		require.NotEmpty(t, dpopProof, "DPoP header must be present")

		if count == 1 {
			// First request: require nonce
			w.Header().Set(DPoPNonceHeader, "test-nonce-123")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "use_dpop_nonce",
			})
			return
		}

		// Second request: verify the proof includes the nonce and succeed
		_, payload := parseDPoPHeader(t, dpopProof)
		assert.Equal(t, "test-nonce-123", payload["nonce"],
			"second attempt must include the server-provided nonce")

		writeTokenResponse(t, w, "nonce-access-token", "DPoP", "nonce-refresh-token")
	}))
	defer server.Close()

	provider := newTestProvider(server.URL)
	config := newTestConfig(server.URL)
	client := NewClient(provider, config)

	dpopKey, err := GenerateDPoPKey()
	require.NoError(t, err)
	client.SetDPoPKey(dpopKey)

	pkce, err := GeneratePKCEParams()
	require.NoError(t, err)

	state, err := GenerateState()
	require.NoError(t, err)

	opts := &AuthCodeOptions{
		State:        state,
		CodeVerifier: pkce.CodeVerifier,
	}

	ctx := context.Background()
	tokens, err := client.Exchange(ctx, "code-with-nonce-retry", opts)
	require.NoError(t, err)
	assert.Equal(t, "nonce-access-token", tokens.AccessToken)
	assert.Equal(t, int32(2), requestCount.Load(), "expected exactly 2 requests (1 nonce challenge + 1 success)")
}

func TestClient_DPoPNonceRetryExhausted(t *testing.T) {
	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := requestCount.Add(1)

		// Always respond with use_dpop_nonce, providing a fresh nonce each time.
		w.Header().Set(DPoPNonceHeader, "fresh-nonce-"+string(rune('0'+count)))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "use_dpop_nonce",
		})
	}))
	defer server.Close()

	provider := newTestProvider(server.URL)
	config := newTestConfig(server.URL)
	client := NewClient(provider, config)

	dpopKey, err := GenerateDPoPKey()
	require.NoError(t, err)
	client.SetDPoPKey(dpopKey)

	pkce, err := GeneratePKCEParams()
	require.NoError(t, err)

	state, err := GenerateState()
	require.NoError(t, err)

	opts := &AuthCodeOptions{
		State:        state,
		CodeVerifier: pkce.CodeVerifier,
	}

	ctx := context.Background()
	_, err = client.Exchange(ctx, "code-always-nonce", opts)
	assert.ErrorIs(t, err, ErrDPoPNonceRequired,
		"Exchange must return ErrDPoPNonceRequired after exhausting retries")
	assert.Equal(t, int32(MaxDPoPNonceRetries), requestCount.Load(),
		"client must attempt exactly MaxDPoPNonceRetries requests")
}

func TestClient_DPoPRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify DPoP header is present
		dpopProof := r.Header.Get("DPoP")
		require.NotEmpty(t, dpopProof, "DPoP header must be present for refresh")

		// Validate the proof structure
		header, payload := parseDPoPHeader(t, dpopProof)
		assert.Equal(t, "dpop+jwt", header["typ"])
		assert.Equal(t, "ES256", header["alg"])
		assert.Equal(t, "POST", payload["htm"])
		assert.NotEmpty(t, payload["htu"])

		// Verify grant_type is refresh_token
		err := r.ParseForm()
		require.NoError(t, err)
		assert.Equal(t, "refresh_token", r.FormValue("grant_type"))
		assert.Equal(t, "original-refresh-token", r.FormValue("refresh_token"))

		writeTokenResponse(t, w, "refreshed-access-token", "DPoP", "refreshed-refresh-token")
	}))
	defer server.Close()

	provider := newTestProvider(server.URL)
	config := newTestConfig(server.URL)
	client := NewClient(provider, config)

	dpopKey, err := GenerateDPoPKey()
	require.NoError(t, err)
	client.SetDPoPKey(dpopKey)

	// Verify SetDPoPKey / GetDPoPKey round-trip returns the same key
	retrievedKey := client.GetDPoPKey()
	require.NotNil(t, retrievedKey)
	assert.Equal(t, dpopKey.PrivateKey.D, retrievedKey.PrivateKey.D,
		"GetDPoPKey must return the same key that was set")

	ctx := context.Background()
	tokens, err := client.Refresh(ctx, "original-refresh-token")
	require.NoError(t, err)
	assert.Equal(t, "refreshed-access-token", tokens.AccessToken)
	assert.Equal(t, "refreshed-refresh-token", tokens.RefreshToken)
}

func TestClient_NoDPoPBackwardCompat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify that NO DPoP header is sent when the client has no DPoP key.
		dpopProof := r.Header.Get("DPoP")
		assert.Empty(t, dpopProof, "DPoP header must NOT be present without a DPoP key")

		writeTokenResponse(t, w, "bearer-access-token", "Bearer", "bearer-refresh-token")
	}))
	defer server.Close()

	provider := newTestProvider(server.URL)
	config := newTestConfig(server.URL)

	// Create client WITHOUT setting a DPoP key
	client := NewClient(provider, config)

	// Verify no DPoP key is set
	assert.Nil(t, client.GetDPoPKey(), "new client must have nil DPoP key")

	pkce, err := GeneratePKCEParams()
	require.NoError(t, err)

	state, err := GenerateState()
	require.NoError(t, err)

	opts := &AuthCodeOptions{
		State:        state,
		CodeVerifier: pkce.CodeVerifier,
	}

	ctx := context.Background()
	tokens, err := client.Exchange(ctx, "bearer-auth-code", opts)
	require.NoError(t, err)
	assert.Equal(t, "bearer-access-token", tokens.AccessToken)
	assert.Equal(t, "Bearer", tokens.TokenType)
}

func TestClient_DPoPUserInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/userinfo":
			// Verify Authorization header uses "DPoP" scheme, not "Bearer"
			authHeader := r.Header.Get("Authorization")
			assert.True(t, strings.HasPrefix(authHeader, "DPoP "),
				"Authorization header must start with 'DPoP ' when DPoP key is set, got: %s", authHeader)

			accessToken := strings.TrimPrefix(authHeader, "DPoP ")
			assert.Equal(t, "dpop-bound-access-token", accessToken)

			// Verify DPoP proof header is present
			dpopProof := r.Header.Get("DPoP")
			require.NotEmpty(t, dpopProof, "DPoP header must be present for userinfo")

			header, payload := parseDPoPHeader(t, dpopProof)
			assert.Equal(t, "dpop+jwt", header["typ"])
			assert.Equal(t, "ES256", header["alg"])
			assert.Equal(t, "GET", payload["htm"])

			// The 'ath' claim must be present and contain the access token hash
			athClaim, ok := payload["ath"].(string)
			assert.True(t, ok, "DPoP proof must contain 'ath' claim for resource requests")
			assert.NotEmpty(t, athClaim, "ath claim must not be empty")

			// Verify ath is a valid base64url-encoded SHA-256 hash
			athBytes, err := base64.RawURLEncoding.DecodeString(athClaim)
			assert.NoError(t, err, "ath must be valid base64url")
			assert.Len(t, athBytes, 32, "ath must be SHA-256 hash (32 bytes)")

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sub":   "dpop-user-123",
				"email": "dpop-user@example.com",
				"name":  "DPoP User",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	provider := newTestProvider(server.URL)
	config := newTestConfig(server.URL)
	client := NewClient(provider, config)

	dpopKey, err := GenerateDPoPKey()
	require.NoError(t, err)
	client.SetDPoPKey(dpopKey)

	ctx := context.Background()
	userInfo, err := client.UserInfo(ctx, "dpop-bound-access-token")
	require.NoError(t, err)
	assert.Equal(t, "dpop-user-123", userInfo.Subject)
	assert.Equal(t, "dpop-user@example.com", userInfo.Email)
	assert.Equal(t, "DPoP User", userInfo.Name)
}

func TestProvider_SupportsDPoP(t *testing.T) {
	provider := &Provider{
		Issuer:                        "https://auth.example.com",
		AuthorizationEndpoint:         "https://auth.example.com/authorize",
		TokenEndpoint:                 "https://auth.example.com/token",
		JwksURI:                       "https://auth.example.com/jwks",
		DPoPSigningAlgValuesSupported: []string{"ES256", "ES384"},
	}

	assert.True(t, provider.SupportsDPoP(),
		"SupportsDPoP must return true when ES256 is in DPoPSigningAlgValuesSupported")
}

func TestProvider_SupportsDPoP_NotAdvertised(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		provider := &Provider{
			Issuer:                        "https://auth.example.com",
			AuthorizationEndpoint:         "https://auth.example.com/authorize",
			TokenEndpoint:                 "https://auth.example.com/token",
			JwksURI:                       "https://auth.example.com/jwks",
			DPoPSigningAlgValuesSupported: []string{},
		}

		assert.False(t, provider.SupportsDPoP(),
			"SupportsDPoP must return false when DPoPSigningAlgValuesSupported is empty")
	})

	t.Run("nil slice", func(t *testing.T) {
		provider := &Provider{
			Issuer:                "https://auth.example.com",
			AuthorizationEndpoint: "https://auth.example.com/authorize",
			TokenEndpoint:         "https://auth.example.com/token",
			JwksURI:               "https://auth.example.com/jwks",
		}

		assert.False(t, provider.SupportsDPoP(),
			"SupportsDPoP must return false when DPoPSigningAlgValuesSupported is nil")
	})

	t.Run("only unsupported algorithms", func(t *testing.T) {
		provider := &Provider{
			Issuer:                        "https://auth.example.com",
			AuthorizationEndpoint:         "https://auth.example.com/authorize",
			TokenEndpoint:                 "https://auth.example.com/token",
			JwksURI:                       "https://auth.example.com/jwks",
			DPoPSigningAlgValuesSupported: []string{"RS256", "ES384"},
		}

		assert.False(t, provider.SupportsDPoP(),
			"SupportsDPoP must return false when ES256 is not listed")
	})
}

func TestTokenResponse_DPoPKeyRoundTrip(t *testing.T) {
	t.Run("successful round-trip", func(t *testing.T) {
		dpopKey, err := GenerateDPoPKey()
		require.NoError(t, err)

		tokenResp := &TokenResponse{
			AccessToken: "access-token-123",
			TokenType:   "DPoP",
		}

		// Set the DPoP key on the token response
		err = tokenResp.SetDPoPKey(dpopKey)
		require.NoError(t, err)
		assert.NotEmpty(t, tokenResp.DPoPKeyPEM, "DPoPKeyPEM must be populated after SetDPoPKey")
		assert.True(t, strings.Contains(tokenResp.DPoPKeyPEM, "BEGIN EC PRIVATE KEY"),
			"DPoPKeyPEM must contain PEM header")

		// Retrieve the key from the token response
		restored, err := tokenResp.GetDPoPKey()
		require.NoError(t, err)
		require.NotNil(t, restored)

		// Verify the restored key can generate a valid proof
		proof, err := restored.GenerateProof(&DPoPProofOptions{
			HTTPMethod: "POST",
			HTTPUri:    "https://example.com/token",
		})
		require.NoError(t, err)
		assert.NotEmpty(t, proof)

		// Verify the proof has correct structure
		header, payload := parseDPoPHeader(t, proof)
		assert.Equal(t, "dpop+jwt", header["typ"])
		assert.Equal(t, "ES256", header["alg"])
		assert.Equal(t, "POST", payload["htm"])
		assert.Equal(t, "https://example.com/token", payload["htu"])

		// Verify the key material matches the original
		assert.Equal(t, dpopKey.PrivateKey.D.Bytes(), restored.PrivateKey.D.Bytes(),
			"restored key D value must match original")
		assert.Equal(t, dpopKey.PrivateKey.PublicKey.X.Bytes(), restored.PrivateKey.PublicKey.X.Bytes(),
			"restored key X value must match original")
		assert.Equal(t, dpopKey.PrivateKey.PublicKey.Y.Bytes(), restored.PrivateKey.PublicKey.Y.Bytes(),
			"restored key Y value must match original")
	})

	t.Run("SetDPoPKey with nil key returns error", func(t *testing.T) {
		tokenResp := &TokenResponse{
			AccessToken: "access-token-123",
		}

		err := tokenResp.SetDPoPKey(nil)
		assert.ErrorIs(t, err, ErrDPoPKeyGeneration,
			"SetDPoPKey(nil) must return ErrDPoPKeyGeneration")
	})

	t.Run("GetDPoPKey on empty PEM returns error", func(t *testing.T) {
		tokenResp := &TokenResponse{
			AccessToken: "access-token-123",
			DPoPKeyPEM:  "",
		}

		_, err := tokenResp.GetDPoPKey()
		assert.ErrorIs(t, err, ErrDPoPInvalidProof,
			"GetDPoPKey with empty PEM must return ErrDPoPInvalidProof")
	})

	t.Run("GetDPoPKey on invalid PEM returns error", func(t *testing.T) {
		tokenResp := &TokenResponse{
			AccessToken: "access-token-123",
			DPoPKeyPEM:  "not-a-valid-pem-block",
		}

		_, err := tokenResp.GetDPoPKey()
		assert.ErrorIs(t, err, ErrDPoPInvalidProof,
			"GetDPoPKey with invalid PEM must return ErrDPoPInvalidProof")
	})
}
