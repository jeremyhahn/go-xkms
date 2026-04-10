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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthCodeOptions_Validate(t *testing.T) {
	t.Run("valid options", func(t *testing.T) {
		opts := &AuthCodeOptions{
			State:        "valid-state",
			CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		}
		err := opts.Validate()
		assert.NoError(t, err)
	})

	t.Run("missing state", func(t *testing.T) {
		opts := &AuthCodeOptions{
			CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		}
		err := opts.Validate()
		assert.ErrorIs(t, err, ErrInvalidState)
	})

	t.Run("missing code verifier", func(t *testing.T) {
		opts := &AuthCodeOptions{
			State: "valid-state",
		}
		err := opts.Validate()
		assert.ErrorIs(t, err, ErrInvalidCodeVerifier)
	})

	t.Run("invalid code verifier length", func(t *testing.T) {
		opts := &AuthCodeOptions{
			State:        "valid-state",
			CodeVerifier: "too-short",
		}
		err := opts.Validate()
		assert.ErrorIs(t, err, ErrInvalidCodeVerifier)
	})
}

func TestNewClient(t *testing.T) {
	provider := &Provider{
		Issuer:                "https://auth.example.com",
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
		JwksURI:               "https://auth.example.com/jwks",
	}

	config := &ProviderConfig{
		Issuer:      "https://auth.example.com",
		ClientID:    "client-123",
		RedirectURL: "http://localhost:8080/callback",
	}

	client := NewClient(provider, config)
	assert.NotNil(t, client)
	assert.Equal(t, provider, client.GetProvider())
	assert.Equal(t, config, client.GetConfig())
}

func TestClient_AuthCodeURL(t *testing.T) {
	provider := &Provider{
		Issuer:                "https://auth.example.com",
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
		JwksURI:               "https://auth.example.com/jwks",
	}

	config := &ProviderConfig{
		Issuer:      "https://auth.example.com",
		ClientID:    "client-123",
		RedirectURL: "http://localhost:8080/callback",
		Scopes:      []string{"openid", "profile"},
	}

	client := NewClient(provider, config)

	t.Run("generates valid auth URL", func(t *testing.T) {
		opts := &AuthCodeOptions{
			State:        "test-state",
			Nonce:        "test-nonce",
			CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		}

		authURL, err := client.AuthCodeURL(opts)
		require.NoError(t, err)

		parsed, err := url.Parse(authURL)
		require.NoError(t, err)

		assert.Equal(t, "auth.example.com", parsed.Host)
		assert.Equal(t, "/authorize", parsed.Path)

		params := parsed.Query()
		assert.Equal(t, "code", params.Get("response_type"))
		assert.Equal(t, "client-123", params.Get("client_id"))
		assert.Equal(t, "http://localhost:8080/callback", params.Get("redirect_uri"))
		assert.Equal(t, "openid profile", params.Get("scope"))
		assert.Equal(t, "test-state", params.Get("state"))
		assert.Equal(t, "test-nonce", params.Get("nonce"))
		assert.Equal(t, "S256", params.Get("code_challenge_method"))
		assert.NotEmpty(t, params.Get("code_challenge"))
	})

	t.Run("generates auth URL without nonce", func(t *testing.T) {
		opts := &AuthCodeOptions{
			State:        "test-state",
			CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		}

		authURL, err := client.AuthCodeURL(opts)
		require.NoError(t, err)

		parsed, err := url.Parse(authURL)
		require.NoError(t, err)

		params := parsed.Query()
		assert.Empty(t, params.Get("nonce"))
	})

	t.Run("includes additional parameters", func(t *testing.T) {
		opts := &AuthCodeOptions{
			State:        "test-state",
			CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			AdditionalParams: map[string]string{
				"login_hint": "user@example.com",
				"prompt":     "consent",
			},
		}

		authURL, err := client.AuthCodeURL(opts)
		require.NoError(t, err)

		parsed, err := url.Parse(authURL)
		require.NoError(t, err)

		params := parsed.Query()
		assert.Equal(t, "user@example.com", params.Get("login_hint"))
		assert.Equal(t, "consent", params.Get("prompt"))
	})

	t.Run("fails with uninitialized provider", func(t *testing.T) {
		uninitClient := NewClient(&Provider{}, config)
		opts := &AuthCodeOptions{
			State:        "test-state",
			CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		}

		_, err := uninitClient.AuthCodeURL(opts)
		assert.ErrorIs(t, err, ErrProviderNotInitialized)
	})

	t.Run("fails with nil provider", func(t *testing.T) {
		nilClient := NewClient(nil, config)
		opts := &AuthCodeOptions{
			State:        "test-state",
			CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		}

		_, err := nilClient.AuthCodeURL(opts)
		assert.ErrorIs(t, err, ErrProviderNotInitialized)
	})

	t.Run("fails with invalid options", func(t *testing.T) {
		opts := &AuthCodeOptions{
			State: "test-state",
			// Missing CodeVerifier
		}

		_, err := client.AuthCodeURL(opts)
		assert.ErrorIs(t, err, ErrInvalidCodeVerifier)
	})
}

func createMockTokenServer(t *testing.T, privateKey *rsa.PrivateKey) *httptest.Server {
	mux := http.NewServeMux()

	// Token endpoint
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		grantType := r.FormValue("grant_type")
		if grantType == "authorization_code" {
			code := r.FormValue("code")
			if code == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error":             "invalid_request",
					"error_description": "missing code",
				})
				return
			}

			if code == "invalid_code" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error":             "invalid_grant",
					"error_description": "invalid code",
				})
				return
			}
		} else if grantType == "refresh_token" {
			refreshToken := r.FormValue("refresh_token")
			if refreshToken == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error":             "invalid_request",
					"error_description": "missing refresh_token",
				})
				return
			}

			if refreshToken == "invalid_refresh" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error":             "invalid_grant",
					"error_description": "invalid refresh token",
				})
				return
			}
		}

		// Generate ID token
		now := time.Now()
		claims := jwt.MapClaims{
			"iss":   "SERVER_URL",
			"sub":   "user-123",
			"aud":   "client-123",
			"exp":   now.Add(1 * time.Hour).Unix(),
			"iat":   now.Unix(),
			"nonce": "test-nonce",
			"email": "user@example.com",
			"name":  "Test User",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "key-1"
		idToken, err := token.SignedString(privateKey)
		if err != nil {
			t.Logf("Failed to sign token: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "access-token-123",
			"token_type":    "Bearer",
			"refresh_token": "refresh-token-456",
			"expires_in":    3600,
			"id_token":      idToken,
			"scope":         "openid profile email",
		})
	})

	// JWKS endpoint
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes())

		jwks := JWKSet{
			Keys: []JWK{
				{
					Kty: "RSA",
					Use: "sig",
					Kid: "key-1",
					Alg: "RS256",
					N:   n,
					E:   e,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	// UserInfo endpoint
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sub":   "user-123",
			"email": "user@example.com",
			"name":  "Test User",
		})
	})

	// Revocation endpoint
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// End session endpoint
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	return httptest.NewServer(mux)
}

func TestClient_Exchange(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	server := createMockTokenServer(t, privateKey)
	defer server.Close()

	provider := &Provider{
		Issuer:                server.URL,
		AuthorizationEndpoint: server.URL + "/authorize",
		TokenEndpoint:         server.URL + "/token",
		JwksURI:               server.URL + "/jwks",
		jwksCache:             &JWKSCache{},
		httpClient:            &http.Client{Timeout: 5 * time.Second},
	}

	config := &ProviderConfig{
		Issuer:      server.URL,
		ClientID:    "client-123",
		RedirectURL: "http://localhost:8080/callback",
	}

	client := NewClient(provider, config)

	t.Run("exchanges code for tokens", func(t *testing.T) {
		opts := &AuthCodeOptions{
			State:        "test-state",
			Nonce:        "test-nonce",
			CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		}

		ctx := context.Background()
		tokens, err := client.Exchange(ctx, "valid-code", opts)
		require.NoError(t, err)
		assert.NotNil(t, tokens)
		assert.Equal(t, "access-token-123", tokens.AccessToken)
		assert.Equal(t, "Bearer", tokens.TokenType)
		assert.Equal(t, "refresh-token-456", tokens.RefreshToken)
		assert.NotEmpty(t, tokens.IDToken)
	})

	t.Run("fails with empty code", func(t *testing.T) {
		opts := &AuthCodeOptions{
			State:        "test-state",
			CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		}

		ctx := context.Background()
		_, err := client.Exchange(ctx, "", opts)
		assert.ErrorIs(t, err, ErrTokenExchangeFailed)
	})

	t.Run("fails with uninitialized provider", func(t *testing.T) {
		uninitClient := NewClient(&Provider{}, config)
		opts := &AuthCodeOptions{
			State:        "test-state",
			CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		}

		ctx := context.Background()
		_, err := uninitClient.Exchange(ctx, "code", opts)
		assert.ErrorIs(t, err, ErrProviderNotInitialized)
	})

	t.Run("includes client secret for confidential clients", func(t *testing.T) {
		configWithSecret := &ProviderConfig{
			Issuer:       server.URL,
			ClientID:     "client-123",
			ClientSecret: "client-secret",
			RedirectURL:  "http://localhost:8080/callback",
		}
		clientWithSecret := NewClient(provider, configWithSecret)

		opts := &AuthCodeOptions{
			State:        "test-state",
			CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		}

		ctx := context.Background()
		tokens, err := clientWithSecret.Exchange(ctx, "valid-code", opts)
		require.NoError(t, err)
		assert.NotNil(t, tokens)
	})
}

func TestClient_Refresh(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	server := createMockTokenServer(t, privateKey)
	defer server.Close()

	provider := &Provider{
		Issuer:                server.URL,
		AuthorizationEndpoint: server.URL + "/authorize",
		TokenEndpoint:         server.URL + "/token",
		JwksURI:               server.URL + "/jwks",
		jwksCache:             &JWKSCache{},
		httpClient:            &http.Client{Timeout: 5 * time.Second},
	}

	config := &ProviderConfig{
		Issuer:      server.URL,
		ClientID:    "client-123",
		RedirectURL: "http://localhost:8080/callback",
	}

	client := NewClient(provider, config)

	t.Run("refreshes tokens", func(t *testing.T) {
		ctx := context.Background()
		tokens, err := client.Refresh(ctx, "valid-refresh-token")
		require.NoError(t, err)
		assert.NotNil(t, tokens)
		assert.Equal(t, "access-token-123", tokens.AccessToken)
	})

	t.Run("fails with empty refresh token", func(t *testing.T) {
		ctx := context.Background()
		_, err := client.Refresh(ctx, "")
		assert.ErrorIs(t, err, ErrMissingRefreshToken)
	})

	t.Run("fails with uninitialized provider", func(t *testing.T) {
		uninitClient := NewClient(&Provider{}, config)
		ctx := context.Background()
		_, err := uninitClient.Refresh(ctx, "token")
		assert.ErrorIs(t, err, ErrProviderNotInitialized)
	})

	t.Run("includes client secret for confidential clients", func(t *testing.T) {
		configWithSecret := &ProviderConfig{
			Issuer:       server.URL,
			ClientID:     "client-123",
			ClientSecret: "client-secret",
			RedirectURL:  "http://localhost:8080/callback",
		}
		clientWithSecret := NewClient(provider, configWithSecret)

		ctx := context.Background()
		tokens, err := clientWithSecret.Refresh(ctx, "valid-refresh-token")
		require.NoError(t, err)
		assert.NotNil(t, tokens)
	})
}

func TestClient_VerifyIDToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	server := createMockTokenServer(t, privateKey)
	defer server.Close()

	provider := &Provider{
		Issuer:                server.URL,
		AuthorizationEndpoint: server.URL + "/authorize",
		TokenEndpoint:         server.URL + "/token",
		JwksURI:               server.URL + "/jwks",
		jwksCache:             &JWKSCache{},
		httpClient:            &http.Client{Timeout: 5 * time.Second},
	}

	config := &ProviderConfig{
		Issuer:      server.URL,
		ClientID:    "client-123",
		RedirectURL: "http://localhost:8080/callback",
	}

	client := NewClient(provider, config)

	t.Run("verifies valid ID token", func(t *testing.T) {
		// Generate a valid ID token
		now := time.Now()
		claims := jwt.MapClaims{
			"iss":   server.URL,
			"sub":   "user-123",
			"aud":   "client-123",
			"exp":   now.Add(1 * time.Hour).Unix(),
			"iat":   now.Unix(),
			"nonce": "test-nonce",
			"email": "user@example.com",
			"name":  "Test User",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "key-1"
		idToken, err := token.SignedString(privateKey)
		require.NoError(t, err)

		ctx := context.Background()
		idClaims, err := client.VerifyIDToken(ctx, idToken, "test-nonce")
		require.NoError(t, err)
		assert.Equal(t, "user-123", idClaims.Subject)
		assert.Equal(t, "user@example.com", idClaims.Email)
		assert.Equal(t, "Test User", idClaims.Name)
	})

	t.Run("verifies token without kid in header", func(t *testing.T) {
		now := time.Now()
		claims := jwt.MapClaims{
			"iss": server.URL,
			"sub": "user-123",
			"aud": "client-123",
			"exp": now.Add(1 * time.Hour).Unix(),
			"iat": now.Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		// No kid set in header
		idToken, err := token.SignedString(privateKey)
		require.NoError(t, err)

		ctx := context.Background()
		idClaims, err := client.VerifyIDToken(ctx, idToken, "")
		require.NoError(t, err)
		assert.Equal(t, "user-123", idClaims.Subject)
	})

	t.Run("fails with invalid nonce", func(t *testing.T) {
		now := time.Now()
		claims := jwt.MapClaims{
			"iss":   server.URL,
			"sub":   "user-123",
			"aud":   "client-123",
			"exp":   now.Add(1 * time.Hour).Unix(),
			"iat":   now.Unix(),
			"nonce": "wrong-nonce",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "key-1"
		idToken, err := token.SignedString(privateKey)
		require.NoError(t, err)

		ctx := context.Background()
		_, err = client.VerifyIDToken(ctx, idToken, "expected-nonce")
		assert.ErrorIs(t, err, ErrInvalidNonce)
	})

	t.Run("fails with wrong audience", func(t *testing.T) {
		now := time.Now()
		claims := jwt.MapClaims{
			"iss": server.URL,
			"sub": "user-123",
			"aud": "wrong-client",
			"exp": now.Add(1 * time.Hour).Unix(),
			"iat": now.Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "key-1"
		idToken, err := token.SignedString(privateKey)
		require.NoError(t, err)

		ctx := context.Background()
		_, err = client.VerifyIDToken(ctx, idToken, "")
		assert.ErrorIs(t, err, ErrInvalidAudience)
	})

	t.Run("fails with wrong issuer", func(t *testing.T) {
		now := time.Now()
		claims := jwt.MapClaims{
			"iss": "https://wrong-issuer.com",
			"sub": "user-123",
			"aud": "client-123",
			"exp": now.Add(1 * time.Hour).Unix(),
			"iat": now.Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "key-1"
		idToken, err := token.SignedString(privateKey)
		require.NoError(t, err)

		ctx := context.Background()
		_, err = client.VerifyIDToken(ctx, idToken, "")
		assert.ErrorIs(t, err, ErrInvalidIssuerClaim)
	})

	t.Run("fails with expired token", func(t *testing.T) {
		now := time.Now()
		claims := jwt.MapClaims{
			"iss": server.URL,
			"sub": "user-123",
			"aud": "client-123",
			"exp": now.Add(-1 * time.Hour).Unix(), // Expired
			"iat": now.Add(-2 * time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "key-1"
		idToken, err := token.SignedString(privateKey)
		require.NoError(t, err)

		ctx := context.Background()
		_, err = client.VerifyIDToken(ctx, idToken, "")
		assert.Error(t, err)
	})

	t.Run("fails with empty ID token", func(t *testing.T) {
		ctx := context.Background()
		_, err := client.VerifyIDToken(ctx, "", "")
		assert.ErrorIs(t, err, ErrInvalidIDToken)
	})

	t.Run("fails with uninitialized provider", func(t *testing.T) {
		uninitClient := NewClient(&Provider{}, config)
		ctx := context.Background()
		_, err := uninitClient.VerifyIDToken(ctx, "token", "")
		assert.ErrorIs(t, err, ErrProviderNotInitialized)
	})

	t.Run("fails with malformed token", func(t *testing.T) {
		ctx := context.Background()
		_, err := client.VerifyIDToken(ctx, "not-a-valid-jwt", "")
		assert.ErrorIs(t, err, ErrInvalidIDToken)
	})

	t.Run("fails with invalid signature", func(t *testing.T) {
		// Generate token with a different key
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		now := time.Now()
		claims := jwt.MapClaims{
			"iss": server.URL,
			"sub": "user-123",
			"aud": "client-123",
			"exp": now.Add(1 * time.Hour).Unix(),
			"iat": now.Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "key-1"
		idToken, err := token.SignedString(otherKey)
		require.NoError(t, err)

		ctx := context.Background()
		_, err = client.VerifyIDToken(ctx, idToken, "")
		assert.ErrorIs(t, err, ErrSignatureVerification)
	})
}

func TestClient_UserInfo(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	server := createMockTokenServer(t, privateKey)
	defer server.Close()

	provider := &Provider{
		Issuer:                server.URL,
		AuthorizationEndpoint: server.URL + "/authorize",
		TokenEndpoint:         server.URL + "/token",
		UserinfoEndpoint:      server.URL + "/userinfo",
		JwksURI:               server.URL + "/jwks",
		jwksCache:             &JWKSCache{},
		httpClient:            &http.Client{Timeout: 5 * time.Second},
	}

	config := &ProviderConfig{
		Issuer:      server.URL,
		ClientID:    "client-123",
		RedirectURL: "http://localhost:8080/callback",
	}

	client := NewClient(provider, config)

	t.Run("fetches user info", func(t *testing.T) {
		ctx := context.Background()
		userInfo, err := client.UserInfo(ctx, "valid-access-token")
		require.NoError(t, err)
		assert.Equal(t, "user-123", userInfo.Subject)
		assert.Equal(t, "user@example.com", userInfo.Email)
		assert.Equal(t, "Test User", userInfo.Name)
	})

	t.Run("fails with empty access token", func(t *testing.T) {
		ctx := context.Background()
		_, err := client.UserInfo(ctx, "")
		assert.ErrorIs(t, err, ErrUserInfoFailed)
	})

	t.Run("fails without userinfo endpoint", func(t *testing.T) {
		noUserinfoProvider := &Provider{
			Issuer:                server.URL,
			AuthorizationEndpoint: server.URL + "/authorize",
			TokenEndpoint:         server.URL + "/token",
			JwksURI:               server.URL + "/jwks",
		}
		noUserinfoClient := NewClient(noUserinfoProvider, config)

		ctx := context.Background()
		_, err := noUserinfoClient.UserInfo(ctx, "token")
		assert.ErrorIs(t, err, ErrUserInfoFailed)
	})

	t.Run("fails with uninitialized provider", func(t *testing.T) {
		uninitClient := NewClient(&Provider{}, config)
		ctx := context.Background()
		_, err := uninitClient.UserInfo(ctx, "token")
		assert.ErrorIs(t, err, ErrProviderNotInitialized)
	})
}

func TestClient_RevokeToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	server := createMockTokenServer(t, privateKey)
	defer server.Close()

	provider := &Provider{
		Issuer:                server.URL,
		AuthorizationEndpoint: server.URL + "/authorize",
		TokenEndpoint:         server.URL + "/token",
		RevocationEndpoint:    server.URL + "/revoke",
		JwksURI:               server.URL + "/jwks",
		jwksCache:             &JWKSCache{},
		httpClient:            &http.Client{Timeout: 5 * time.Second},
	}

	config := &ProviderConfig{
		Issuer:      server.URL,
		ClientID:    "client-123",
		RedirectURL: "http://localhost:8080/callback",
	}

	client := NewClient(provider, config)

	t.Run("revokes token", func(t *testing.T) {
		ctx := context.Background()
		err := client.RevokeToken(ctx, "access-token", "access_token")
		assert.NoError(t, err)
	})

	t.Run("revokes token without type hint", func(t *testing.T) {
		ctx := context.Background()
		err := client.RevokeToken(ctx, "some-token", "")
		assert.NoError(t, err)
	})

	t.Run("revokes token with client secret", func(t *testing.T) {
		configWithSecret := &ProviderConfig{
			Issuer:       server.URL,
			ClientID:     "client-123",
			ClientSecret: "client-secret",
			RedirectURL:  "http://localhost:8080/callback",
		}
		clientWithSecret := NewClient(provider, configWithSecret)

		ctx := context.Background()
		err := clientWithSecret.RevokeToken(ctx, "access-token", "access_token")
		assert.NoError(t, err)
	})

	t.Run("fails with empty token", func(t *testing.T) {
		ctx := context.Background()
		err := client.RevokeToken(ctx, "", "")
		assert.ErrorIs(t, err, ErrHTTPRequest)
	})

	t.Run("fails without revocation endpoint", func(t *testing.T) {
		noRevocationProvider := &Provider{
			Issuer:                server.URL,
			AuthorizationEndpoint: server.URL + "/authorize",
			TokenEndpoint:         server.URL + "/token",
			JwksURI:               server.URL + "/jwks",
		}
		noRevocationClient := NewClient(noRevocationProvider, config)

		ctx := context.Background()
		err := noRevocationClient.RevokeToken(ctx, "token", "")
		assert.ErrorIs(t, err, ErrHTTPRequest)
	})

	t.Run("fails with uninitialized provider", func(t *testing.T) {
		uninitClient := NewClient(&Provider{}, config)
		ctx := context.Background()
		err := uninitClient.RevokeToken(ctx, "token", "")
		assert.ErrorIs(t, err, ErrProviderNotInitialized)
	})
}

func TestClient_LogoutURL(t *testing.T) {
	provider := &Provider{
		Issuer:                "https://auth.example.com",
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
		EndSessionEndpoint:    "https://auth.example.com/logout",
		JwksURI:               "https://auth.example.com/jwks",
	}

	config := &ProviderConfig{
		Issuer:      "https://auth.example.com",
		ClientID:    "client-123",
		RedirectURL: "http://localhost:8080/callback",
	}

	client := NewClient(provider, config)

	t.Run("generates logout URL", func(t *testing.T) {
		logoutURL, err := client.LogoutURL("id-token", "http://localhost:8080", "state-123")
		require.NoError(t, err)

		parsed, err := url.Parse(logoutURL)
		require.NoError(t, err)

		assert.Equal(t, "/logout", parsed.Path)
		params := parsed.Query()
		assert.Equal(t, "client-123", params.Get("client_id"))
		assert.Equal(t, "id-token", params.Get("id_token_hint"))
		assert.Equal(t, "http://localhost:8080", params.Get("post_logout_redirect_uri"))
		assert.Equal(t, "state-123", params.Get("state"))
	})

	t.Run("generates logout URL without optional params", func(t *testing.T) {
		logoutURL, err := client.LogoutURL("", "", "")
		require.NoError(t, err)

		parsed, err := url.Parse(logoutURL)
		require.NoError(t, err)

		params := parsed.Query()
		assert.Equal(t, "client-123", params.Get("client_id"))
		assert.Empty(t, params.Get("id_token_hint"))
		assert.Empty(t, params.Get("post_logout_redirect_uri"))
		assert.Empty(t, params.Get("state"))
	})

	t.Run("fails without end session endpoint", func(t *testing.T) {
		noLogoutProvider := &Provider{
			Issuer:                "https://auth.example.com",
			AuthorizationEndpoint: "https://auth.example.com/authorize",
			TokenEndpoint:         "https://auth.example.com/token",
			JwksURI:               "https://auth.example.com/jwks",
		}
		noLogoutClient := NewClient(noLogoutProvider, config)

		_, err := noLogoutClient.LogoutURL("", "", "")
		assert.ErrorIs(t, err, ErrHTTPRequest)
	})

	t.Run("fails with uninitialized provider", func(t *testing.T) {
		uninitClient := NewClient(&Provider{}, config)
		_, err := uninitClient.LogoutURL("", "", "")
		assert.ErrorIs(t, err, ErrProviderNotInitialized)
	})
}

func TestVerifyAccessTokenHash(t *testing.T) {
	t.Run("accepts empty at_hash", func(t *testing.T) {
		err := VerifyAccessTokenHash("access-token", "", "RS256")
		assert.NoError(t, err)
	})

	t.Run("verifies valid at_hash for RS256", func(t *testing.T) {
		accessToken := "test-access-token"
		// Calculate expected hash
		hasher := sha256.New()
		hasher.Write([]byte(accessToken))
		hash := hasher.Sum(nil)
		atHash := base64.RawURLEncoding.EncodeToString(hash[:len(hash)/2])

		err := VerifyAccessTokenHash(accessToken, atHash, "RS256")
		assert.NoError(t, err)
	})

	t.Run("verifies valid at_hash for ES256", func(t *testing.T) {
		accessToken := "test-access-token"
		hasher := sha256.New()
		hasher.Write([]byte(accessToken))
		hash := hasher.Sum(nil)
		atHash := base64.RawURLEncoding.EncodeToString(hash[:len(hash)/2])

		err := VerifyAccessTokenHash(accessToken, atHash, "ES256")
		assert.NoError(t, err)
	})

	t.Run("verifies valid at_hash for PS256", func(t *testing.T) {
		accessToken := "test-access-token"
		hasher := sha256.New()
		hasher.Write([]byte(accessToken))
		hash := hasher.Sum(nil)
		atHash := base64.RawURLEncoding.EncodeToString(hash[:len(hash)/2])

		err := VerifyAccessTokenHash(accessToken, atHash, "PS256")
		assert.NoError(t, err)
	})

	t.Run("fails with invalid at_hash", func(t *testing.T) {
		err := VerifyAccessTokenHash("access-token", "invalid-hash", "RS256")
		assert.ErrorIs(t, err, ErrInvalidIDToken)
	})

	t.Run("handles different signing algorithms", func(t *testing.T) {
		// Test that different algorithms use different hash functions
		err := VerifyAccessTokenHash("access-token", "invalid-hash", "RS384")
		assert.ErrorIs(t, err, ErrInvalidIDToken)

		err = VerifyAccessTokenHash("access-token", "invalid-hash", "RS512")
		assert.ErrorIs(t, err, ErrInvalidIDToken)
	})

	t.Run("uses default hash for unknown algorithm", func(t *testing.T) {
		err := VerifyAccessTokenHash("access-token", "invalid-hash", "unknown-alg")
		assert.ErrorIs(t, err, ErrInvalidIDToken)
	})
}

func TestRsaPublicKeyVerifier_Verify(t *testing.T) {
	// Test the verify method exists and returns nil (as expected per implementation)
	verifier := &rsaPublicKeyVerifier{key: nil}
	err := verifier.Verify("signing", []byte("signature"))
	assert.NoError(t, err)
}

func TestParseIDTokenClaims_AllClaims(t *testing.T) {
	// Test parseIDTokenClaims with all possible claims to increase coverage
	t.Run("parses all standard claims", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss":                   "https://issuer.example.com",
			"sub":                   "user-123",
			"aud":                   "client-456",
			"exp":                   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":                   float64(time.Now().Unix()),
			"auth_time":             float64(time.Now().Add(-5 * time.Minute).Unix()),
			"nonce":                 "nonce-value",
			"azp":                   "authorized-party",
			"at_hash":               "access-token-hash",
			"c_hash":                "code-hash",
			"acr":                   "acr-value",
			"email":                 "user@example.com",
			"email_verified":        true,
			"name":                  "Test User",
			"given_name":            "Test",
			"family_name":           "User",
			"preferred_username":    "testuser",
			"picture":               "https://example.com/picture.jpg",
			"profile":               "https://example.com/profile",
			"locale":                "en-US",
			"zoneinfo":              "America/New_York",
			"updated_at":            float64(time.Now().Unix()),
			"phone_number":          "+1234567890",
			"phone_number_verified": true,
			"amr":                   []interface{}{"pwd", "mfa"},
			"address": map[string]interface{}{
				"formatted":      "123 Main St, City, Country",
				"street_address": "123 Main St",
				"locality":       "City",
				"region":         "State",
				"postal_code":    "12345",
				"country":        "Country",
			},
			"custom_claim": "custom_value",
		}

		idClaims, err := parseIDTokenClaims(claims)
		require.NoError(t, err)

		assert.Equal(t, "https://issuer.example.com", idClaims.Issuer)
		assert.Equal(t, "user-123", idClaims.Subject)
		assert.True(t, idClaims.Audience.Contains("client-456"))
		assert.Equal(t, "nonce-value", idClaims.Nonce)
		assert.Equal(t, "authorized-party", idClaims.AuthorizedParty)
		assert.Equal(t, "access-token-hash", idClaims.AccessTokenHash)
		assert.Equal(t, "code-hash", idClaims.CodeHash)
		assert.Equal(t, "acr-value", idClaims.ACR)
		assert.Equal(t, "user@example.com", idClaims.Email)
		assert.True(t, idClaims.EmailVerified)
		assert.Equal(t, "Test User", idClaims.Name)
		assert.Equal(t, "Test", idClaims.GivenName)
		assert.Equal(t, "User", idClaims.FamilyName)
		assert.Equal(t, "testuser", idClaims.PreferredUsername)
		assert.Equal(t, "https://example.com/picture.jpg", idClaims.Picture)
		assert.Equal(t, "https://example.com/profile", idClaims.Profile)
		assert.Equal(t, "en-US", idClaims.Locale)
		assert.Equal(t, "America/New_York", idClaims.Zoneinfo)
		assert.Equal(t, "+1234567890", idClaims.PhoneNumber)
		assert.True(t, idClaims.PhoneNumberVerified)
		assert.Contains(t, idClaims.AMR, "pwd")
		assert.Contains(t, idClaims.AMR, "mfa")
		assert.NotNil(t, idClaims.Address)
		assert.Equal(t, "123 Main St, City, Country", idClaims.Address.Formatted)
		assert.Equal(t, "123 Main St", idClaims.Address.StreetAddress)
		assert.Equal(t, "City", idClaims.Address.Locality)
		assert.Equal(t, "State", idClaims.Address.Region)
		assert.Equal(t, "12345", idClaims.Address.PostalCode)
		assert.Equal(t, "Country", idClaims.Address.Country)
		assert.Equal(t, "custom_value", idClaims.Extra["custom_claim"])
	})

	t.Run("parses audience as array", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": "https://issuer.example.com",
			"sub": "user-123",
			"aud": []interface{}{"client-1", "client-2", "client-3"},
			"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat": float64(time.Now().Unix()),
		}

		idClaims, err := parseIDTokenClaims(claims)
		require.NoError(t, err)

		assert.True(t, idClaims.Audience.Contains("client-1"))
		assert.True(t, idClaims.Audience.Contains("client-2"))
		assert.True(t, idClaims.Audience.Contains("client-3"))
	})

	t.Run("handles missing optional claims", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": "https://issuer.example.com",
			"sub": "user-123",
			"aud": "client-456",
			"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat": float64(time.Now().Unix()),
		}

		idClaims, err := parseIDTokenClaims(claims)
		require.NoError(t, err)

		assert.Equal(t, "", idClaims.Email)
		assert.False(t, idClaims.EmailVerified)
		assert.Nil(t, idClaims.Address)
		assert.Empty(t, idClaims.AMR)
	})

	t.Run("handles empty claims", func(t *testing.T) {
		claims := jwt.MapClaims{}

		idClaims, err := parseIDTokenClaims(claims)
		require.NoError(t, err)

		assert.Equal(t, "", idClaims.Issuer)
		assert.Equal(t, "", idClaims.Subject)
		assert.Empty(t, idClaims.Audience)
	})

	t.Run("handles amr with non-string elements", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": "https://issuer.example.com",
			"sub": "user-123",
			"aud": "client-456",
			"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat": float64(time.Now().Unix()),
			"amr": []interface{}{"pwd", 123, "mfa", nil}, // mixed types
		}

		idClaims, err := parseIDTokenClaims(claims)
		require.NoError(t, err)

		// Only string values should be included
		assert.Contains(t, idClaims.AMR, "pwd")
		assert.Contains(t, idClaims.AMR, "mfa")
		assert.Len(t, idClaims.AMR, 2)
	})

	t.Run("handles audience array with non-string elements", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": "https://issuer.example.com",
			"sub": "user-123",
			"aud": []interface{}{"client-1", 123, "client-2", nil},
			"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat": float64(time.Now().Unix()),
		}

		idClaims, err := parseIDTokenClaims(claims)
		require.NoError(t, err)

		assert.True(t, idClaims.Audience.Contains("client-1"))
		assert.True(t, idClaims.Audience.Contains("client-2"))
		assert.Len(t, idClaims.Audience, 2)
	})
}

func TestDoTokenRequest_ErrorPaths(t *testing.T) {
	t.Run("handles server error response with error details", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_grant",
				"error_description": "The authorization code has expired",
			})
		}))
		defer server.Close()

		provider := &Provider{
			Issuer:                server.URL,
			AuthorizationEndpoint: server.URL + "/authorize",
			TokenEndpoint:         server.URL + "/token",
			JwksURI:               server.URL + "/jwks",
			httpClient:            &http.Client{Timeout: 5 * time.Second},
		}

		config := &ProviderConfig{
			Issuer:      server.URL,
			ClientID:    "client-123",
			RedirectURL: "http://localhost:8080/callback",
		}

		client := NewClient(provider, config)
		opts := &AuthCodeOptions{
			State:        "test-state",
			CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		}

		ctx := context.Background()
		_, err := client.Exchange(ctx, "expired-code", opts)
		assert.ErrorIs(t, err, ErrTokenExchangeFailed)
	})

	t.Run("handles invalid JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("not valid json"))
		}))
		defer server.Close()

		provider := &Provider{
			Issuer:                server.URL,
			AuthorizationEndpoint: server.URL + "/authorize",
			TokenEndpoint:         server.URL + "/token",
			JwksURI:               server.URL + "/jwks",
			httpClient:            &http.Client{Timeout: 5 * time.Second},
		}

		config := &ProviderConfig{
			Issuer:      server.URL,
			ClientID:    "client-123",
			RedirectURL: "http://localhost:8080/callback",
		}

		client := NewClient(provider, config)
		opts := &AuthCodeOptions{
			State:        "test-state",
			CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		}

		ctx := context.Background()
		_, err := client.Exchange(ctx, "code", opts)
		assert.ErrorIs(t, err, ErrInvalidResponse)
	})

	t.Run("handles server error without error body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		provider := &Provider{
			Issuer:                server.URL,
			AuthorizationEndpoint: server.URL + "/authorize",
			TokenEndpoint:         server.URL + "/token",
			JwksURI:               server.URL + "/jwks",
			httpClient:            &http.Client{Timeout: 5 * time.Second},
		}

		config := &ProviderConfig{
			Issuer:      server.URL,
			ClientID:    "client-123",
			RedirectURL: "http://localhost:8080/callback",
		}

		client := NewClient(provider, config)
		opts := &AuthCodeOptions{
			State:        "test-state",
			CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		}

		ctx := context.Background()
		_, err := client.Exchange(ctx, "code", opts)
		assert.ErrorIs(t, err, ErrTokenExchangeFailed)
	})

	t.Run("handles response without expires_in", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "access-token-123",
				"token_type":    "Bearer",
				"refresh_token": "refresh-token-456",
				// No expires_in
			})
		}))
		defer server.Close()

		provider := &Provider{
			Issuer:                server.URL,
			AuthorizationEndpoint: server.URL + "/authorize",
			TokenEndpoint:         server.URL + "/token",
			JwksURI:               server.URL + "/jwks",
			httpClient:            &http.Client{Timeout: 5 * time.Second},
		}

		config := &ProviderConfig{
			Issuer:      server.URL,
			ClientID:    "client-123",
			RedirectURL: "http://localhost:8080/callback",
		}

		client := NewClient(provider, config)
		opts := &AuthCodeOptions{
			State:        "test-state",
			CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		}

		ctx := context.Background()
		tokens, err := client.Exchange(ctx, "code", opts)
		require.NoError(t, err)
		assert.True(t, tokens.Expiry.IsZero())
	})
}

func TestUserInfo_ErrorPaths(t *testing.T) {
	t.Run("handles non-200 response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		provider := &Provider{
			Issuer:                server.URL,
			AuthorizationEndpoint: server.URL + "/authorize",
			TokenEndpoint:         server.URL + "/token",
			UserinfoEndpoint:      server.URL + "/userinfo",
			JwksURI:               server.URL + "/jwks",
			httpClient:            &http.Client{Timeout: 5 * time.Second},
		}

		config := &ProviderConfig{
			Issuer:      server.URL,
			ClientID:    "client-123",
			RedirectURL: "http://localhost:8080/callback",
		}

		client := NewClient(provider, config)
		ctx := context.Background()
		_, err := client.UserInfo(ctx, "invalid-token")
		assert.ErrorIs(t, err, ErrUserInfoFailed)
	})

	t.Run("handles invalid JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("not valid json"))
		}))
		defer server.Close()

		provider := &Provider{
			Issuer:                server.URL,
			AuthorizationEndpoint: server.URL + "/authorize",
			TokenEndpoint:         server.URL + "/token",
			UserinfoEndpoint:      server.URL + "/userinfo",
			JwksURI:               server.URL + "/jwks",
			httpClient:            &http.Client{Timeout: 5 * time.Second},
		}

		config := &ProviderConfig{
			Issuer:      server.URL,
			ClientID:    "client-123",
			RedirectURL: "http://localhost:8080/callback",
		}

		client := NewClient(provider, config)
		ctx := context.Background()
		_, err := client.UserInfo(ctx, "token")
		assert.ErrorIs(t, err, ErrInvalidResponse)
	})
}

func TestRevokeToken_ErrorPaths(t *testing.T) {
	t.Run("handles non-200/204 response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer server.Close()

		provider := &Provider{
			Issuer:                server.URL,
			AuthorizationEndpoint: server.URL + "/authorize",
			TokenEndpoint:         server.URL + "/token",
			RevocationEndpoint:    server.URL + "/revoke",
			JwksURI:               server.URL + "/jwks",
			httpClient:            &http.Client{Timeout: 5 * time.Second},
		}

		config := &ProviderConfig{
			Issuer:      server.URL,
			ClientID:    "client-123",
			RedirectURL: "http://localhost:8080/callback",
		}

		client := NewClient(provider, config)
		ctx := context.Background()
		err := client.RevokeToken(ctx, "token", "")
		assert.ErrorIs(t, err, ErrHTTPRequest)
	})

	t.Run("handles 204 No Content response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		provider := &Provider{
			Issuer:                server.URL,
			AuthorizationEndpoint: server.URL + "/authorize",
			TokenEndpoint:         server.URL + "/token",
			RevocationEndpoint:    server.URL + "/revoke",
			JwksURI:               server.URL + "/jwks",
			httpClient:            &http.Client{Timeout: 5 * time.Second},
		}

		config := &ProviderConfig{
			Issuer:      server.URL,
			ClientID:    "client-123",
			RedirectURL: "http://localhost:8080/callback",
		}

		client := NewClient(provider, config)
		ctx := context.Background()
		err := client.RevokeToken(ctx, "token", "")
		assert.NoError(t, err)
	})
}
