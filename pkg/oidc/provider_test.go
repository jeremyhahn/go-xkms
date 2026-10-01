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

func TestProviderConfig_Validate(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		config := &ProviderConfig{
			Issuer:      "https://auth.example.com",
			ClientID:    "client-123",
			RedirectURL: "http://localhost:8080/callback",
		}
		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("missing issuer", func(t *testing.T) {
		config := &ProviderConfig{
			ClientID:    "client-123",
			RedirectURL: "http://localhost:8080/callback",
		}
		err := config.Validate()
		assert.ErrorIs(t, err, ErrInvalidIssuer)
	})

	t.Run("missing client ID", func(t *testing.T) {
		config := &ProviderConfig{
			Issuer:      "https://auth.example.com",
			RedirectURL: "http://localhost:8080/callback",
		}
		err := config.Validate()
		assert.ErrorIs(t, err, ErrInvalidClientID)
	})

	t.Run("missing redirect URL", func(t *testing.T) {
		config := &ProviderConfig{
			Issuer:   "https://auth.example.com",
			ClientID: "client-123",
		}
		err := config.Validate()
		assert.ErrorIs(t, err, ErrInvalidRedirectURL)
	})

	t.Run("invalid issuer URL format", func(t *testing.T) {
		config := &ProviderConfig{
			Issuer:      "not-a-url",
			ClientID:    "client-123",
			RedirectURL: "http://localhost:8080/callback",
		}
		err := config.Validate()
		assert.ErrorIs(t, err, ErrInvalidIssuer)
	})

	t.Run("invalid redirect URL format", func(t *testing.T) {
		config := &ProviderConfig{
			Issuer:      "https://auth.example.com",
			ClientID:    "client-123",
			RedirectURL: "not-a-url",
		}
		err := config.Validate()
		assert.ErrorIs(t, err, ErrInvalidRedirectURL)
	})
}

func TestProviderConfig_EffectiveScopes(t *testing.T) {
	t.Run("returns default scopes when none set", func(t *testing.T) {
		config := &ProviderConfig{}
		scopes := config.EffectiveScopes()
		assert.Equal(t, DefaultScopes, scopes)
	})

	t.Run("returns custom scopes when set", func(t *testing.T) {
		config := &ProviderConfig{
			Scopes: []string{"openid", "custom"},
		}
		scopes := config.EffectiveScopes()
		assert.Equal(t, []string{"openid", "custom"}, scopes)
	})
}

func createMockOIDCServer() *httptest.Server {
	mux := http.NewServeMux()

	// Discovery endpoint. The base URL is derived from the incoming
	// request's Host header rather than a placeholder string: httptest
	// always serves plain http on 127.0.0.1, so the resulting endpoints are
	// real, loopback URLs that satisfy the https-or-loopback discovery
	// validation the same way a real-but-local IdP would.
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		metadata := map[string]interface{}{
			"issuer":                                base,
			"authorization_endpoint":                base + "/authorize",
			"token_endpoint":                        base + "/token",
			"userinfo_endpoint":                     base + "/userinfo",
			"jwks_uri":                              base + "/jwks",
			"registration_endpoint":                 base + "/register",
			"revocation_endpoint":                   base + "/revoke",
			"end_session_endpoint":                  base + "/logout",
			"scopes_supported":                      []string{"openid", "profile", "email"},
			"response_types_supported":              []string{"code", "token", "id_token"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":      []string{"S256"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	})

	// JWKS endpoint
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks := JWKSet{
			Keys: []JWK{
				{
					Kty: "RSA",
					Use: "sig",
					Kid: "key-1",
					Alg: "RS256",
					N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
					E:   "AQAB",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	return httptest.NewServer(mux)
}

func TestNewProvider(t *testing.T) {
	server := createMockOIDCServer()
	defer server.Close()

	t.Run("creates provider with discovery", func(t *testing.T) {
		config := &ProviderConfig{
			Issuer:      server.URL,
			ClientID:    "client-123",
			RedirectURL: "http://localhost:8080/callback",
		}

		ctx := context.Background()
		provider, err := NewProvider(ctx, config)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.True(t, provider.IsInitialized())
	})

	t.Run("creates provider without discovery", func(t *testing.T) {
		config := &ProviderConfig{
			Issuer:        server.URL,
			ClientID:      "client-123",
			RedirectURL:   "http://localhost:8080/callback",
			SkipDiscovery: true,
		}

		ctx := context.Background()
		provider, err := NewProvider(ctx, config)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.False(t, provider.IsInitialized())
	})

	t.Run("fails with invalid config", func(t *testing.T) {
		config := &ProviderConfig{
			ClientID:    "client-123",
			RedirectURL: "http://localhost:8080/callback",
		}

		ctx := context.Background()
		_, err := NewProvider(ctx, config)
		assert.ErrorIs(t, err, ErrInvalidIssuer)
	})

	t.Run("fails when discovery fails", func(t *testing.T) {
		config := &ProviderConfig{
			Issuer:      "https://nonexistent.example.com",
			ClientID:    "client-123",
			RedirectURL: "http://localhost:8080/callback",
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err := NewProvider(ctx, config)
		assert.ErrorIs(t, err, ErrDiscoveryFailed)
	})

	t.Run("uses custom HTTP client", func(t *testing.T) {
		config := &ProviderConfig{
			Issuer:      server.URL,
			ClientID:    "client-123",
			RedirectURL: "http://localhost:8080/callback",
			HTTPClient:  &http.Client{Timeout: 10 * time.Second},
		}

		ctx := context.Background()
		provider, err := NewProvider(ctx, config)
		require.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("normalizes issuer with trailing slash", func(t *testing.T) {
		config := &ProviderConfig{
			Issuer:        server.URL + "/",
			ClientID:      "client-123",
			RedirectURL:   "http://localhost:8080/callback",
			SkipDiscovery: true,
		}

		ctx := context.Background()
		provider, err := NewProvider(ctx, config)
		require.NoError(t, err)
		assert.Equal(t, server.URL, provider.Issuer)
	})
}

func TestProvider_Discover(t *testing.T) {
	server := createMockOIDCServer()
	defer server.Close()

	t.Run("discovers endpoints successfully", func(t *testing.T) {
		provider := &Provider{
			Issuer:     server.URL,
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		ctx := context.Background()
		err := provider.Discover(ctx)
		require.NoError(t, err)

		assert.NotEmpty(t, provider.AuthorizationEndpoint)
		assert.NotEmpty(t, provider.TokenEndpoint)
		assert.NotEmpty(t, provider.JwksURI)
		assert.NotEmpty(t, provider.UserinfoEndpoint)
	})

	t.Run("rejects a plain-http authorization endpoint on a non-loopback host", func(t *testing.T) {
		// A compromised or spoofed IdP could point the browser-bound
		// authorization_endpoint at an insecure, attacker-controlled host
		// (go-xkms#1275); Discover must refuse it rather than pass it
		// through to whatever opens it in the user's browser.
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                 "https://example.com",
				"authorization_endpoint": "http://evil.example.com/authorize",
				"token_endpoint":         "https://example.com/token",
				"jwks_uri":               "https://example.com/jwks",
			})
		})
		testServer := httptest.NewServer(mux)
		defer testServer.Close()

		provider := &Provider{
			Issuer:     testServer.URL,
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		err := provider.Discover(context.Background())
		assert.ErrorIs(t, err, ErrInsecureEndpoint)
	})

	t.Run("rejects a plain-http token endpoint even when the authorization endpoint is https", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                 "https://example.com",
				"authorization_endpoint": "https://example.com/authorize",
				"token_endpoint":         "http://evil.example.com/token",
				"jwks_uri":               "https://example.com/jwks",
			})
		})
		testServer := httptest.NewServer(mux)
		defer testServer.Close()

		provider := &Provider{
			Issuer:     testServer.URL,
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		err := provider.Discover(context.Background())
		assert.ErrorIs(t, err, ErrInsecureEndpoint)
	})

	t.Run("accepts https endpoints on a non-loopback host", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                 "https://example.com",
				"authorization_endpoint": "https://example.com/authorize",
				"token_endpoint":         "https://example.com/token",
				"jwks_uri":               "https://example.com/jwks",
			})
		})
		testServer := httptest.NewServer(mux)
		defer testServer.Close()

		provider := &Provider{
			Issuer:     testServer.URL,
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		err := provider.Discover(context.Background())
		require.NoError(t, err)
	})

	t.Run("accepts a plain-http authorization endpoint on loopback", func(t *testing.T) {
		// Development IdPs commonly run unencrypted on the loopback
		// interface; createMockOIDCServer's endpoints already exercise
		// this (they're http://127.0.0.1:<port>/...), so this documents
		// the rule explicitly against 127.0.0.1 rather than relying on
		// that implicit coverage alone.
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			base := "http://" + r.Host
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                 base,
				"authorization_endpoint": base + "/authorize",
				"token_endpoint":         base + "/token",
				"jwks_uri":               base + "/jwks",
			})
		})
		testServer := httptest.NewServer(mux)
		defer testServer.Close()

		provider := &Provider{
			Issuer:     testServer.URL,
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		err := provider.Discover(context.Background())
		require.NoError(t, err)
	})

	t.Run("fails with missing authorization endpoint", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":         "https://example.com",
				"token_endpoint": "https://example.com/token",
				"jwks_uri":       "https://example.com/jwks",
			})
		})
		testServer := httptest.NewServer(mux)
		defer testServer.Close()

		provider := &Provider{
			Issuer:     testServer.URL,
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		err := provider.Discover(context.Background())
		assert.ErrorIs(t, err, ErrMissingAuthEndpoint)
	})

	t.Run("fails with missing token endpoint", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                 "https://example.com",
				"authorization_endpoint": "https://example.com/authorize",
				"jwks_uri":               "https://example.com/jwks",
			})
		})
		testServer := httptest.NewServer(mux)
		defer testServer.Close()

		provider := &Provider{
			Issuer:     testServer.URL,
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		err := provider.Discover(context.Background())
		assert.ErrorIs(t, err, ErrMissingTokenEndpoint)
	})

	t.Run("fails with missing JWKS URI", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                 "https://example.com",
				"authorization_endpoint": "https://example.com/authorize",
				"token_endpoint":         "https://example.com/token",
			})
		})
		testServer := httptest.NewServer(mux)
		defer testServer.Close()

		provider := &Provider{
			Issuer:     testServer.URL,
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		err := provider.Discover(context.Background())
		assert.ErrorIs(t, err, ErrMissingJWKSURI)
	})

	t.Run("fails with non-200 response", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
		testServer := httptest.NewServer(mux)
		defer testServer.Close()

		provider := &Provider{
			Issuer:     testServer.URL,
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		err := provider.Discover(context.Background())
		assert.ErrorIs(t, err, ErrDiscoveryFailed)
	})

	t.Run("fails with invalid JSON response", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("not valid json"))
		})
		testServer := httptest.NewServer(mux)
		defer testServer.Close()

		provider := &Provider{
			Issuer:     testServer.URL,
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		err := provider.Discover(context.Background())
		assert.ErrorIs(t, err, ErrDiscoveryFailed)
	})
}

func TestProvider_FetchJWKS(t *testing.T) {
	server := createMockOIDCServer()
	defer server.Close()

	t.Run("fetches JWKS successfully", func(t *testing.T) {
		provider := &Provider{
			Issuer:     server.URL,
			JwksURI:    server.URL + "/jwks",
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		ctx := context.Background()
		keys, err := provider.FetchJWKS(ctx)
		require.NoError(t, err)
		assert.Len(t, keys, 1)
		assert.Equal(t, "key-1", keys[0].Kid)
		assert.Equal(t, "RSA", keys[0].Kty)
	})

	t.Run("uses cached JWKS", func(t *testing.T) {
		provider := &Provider{
			Issuer:     server.URL,
			JwksURI:    server.URL + "/jwks",
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache: &JWKSCache{
				Keys: []JWK{{
					Kty: "RSA",
					Kid: "cached-key",
				}},
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
		}

		ctx := context.Background()
		keys, err := provider.FetchJWKS(ctx)
		require.NoError(t, err)
		assert.Len(t, keys, 1)
		assert.Equal(t, "cached-key", keys[0].Kid)
	})

	t.Run("fails without JWKS URI", func(t *testing.T) {
		provider := &Provider{
			Issuer:     server.URL,
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		_, err := provider.FetchJWKS(context.Background())
		assert.ErrorIs(t, err, ErrMissingJWKSURI)
	})

	t.Run("fails with non-200 response", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		testServer := httptest.NewServer(mux)
		defer testServer.Close()

		provider := &Provider{
			Issuer:     testServer.URL,
			JwksURI:    testServer.URL + "/jwks",
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		_, err := provider.FetchJWKS(context.Background())
		assert.ErrorIs(t, err, ErrJWKSFetchFailed)
	})

	t.Run("fails with invalid JSON response", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("not valid json"))
		})
		testServer := httptest.NewServer(mux)
		defer testServer.Close()

		provider := &Provider{
			Issuer:     testServer.URL,
			JwksURI:    testServer.URL + "/jwks",
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		_, err := provider.FetchJWKS(context.Background())
		assert.ErrorIs(t, err, ErrJWKSFetchFailed)
	})

	t.Run("refreshes expired cache", func(t *testing.T) {
		provider := &Provider{
			Issuer:     server.URL,
			JwksURI:    server.URL + "/jwks",
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache: &JWKSCache{
				Keys: []JWK{{
					Kty: "RSA",
					Kid: "expired-key",
				}},
				ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
			},
		}

		ctx := context.Background()
		keys, err := provider.FetchJWKS(ctx)
		require.NoError(t, err)
		assert.Len(t, keys, 1)
		assert.Equal(t, "key-1", keys[0].Kid) // Should fetch fresh key
	})
}

func TestProvider_GetSigningKey(t *testing.T) {
	server := createMockOIDCServer()
	defer server.Close()

	t.Run("gets signing key by kid", func(t *testing.T) {
		provider := &Provider{
			Issuer:     server.URL,
			JwksURI:    server.URL + "/jwks",
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		ctx := context.Background()
		key, err := provider.GetSigningKey(ctx, "key-1")
		require.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("gets first signing key when kid is empty", func(t *testing.T) {
		provider := &Provider{
			Issuer:     server.URL,
			JwksURI:    server.URL + "/jwks",
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		ctx := context.Background()
		key, err := provider.GetSigningKey(ctx, "")
		require.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("fails when key not found", func(t *testing.T) {
		provider := &Provider{
			Issuer:     server.URL,
			JwksURI:    server.URL + "/jwks",
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		ctx := context.Background()
		_, err := provider.GetSigningKey(ctx, "nonexistent-key")
		assert.ErrorIs(t, err, ErrNoSigningKey)
	})

	t.Run("skips non-RSA keys", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
			jwks := JWKSet{
				Keys: []JWK{
					{
						Kty: "EC", // Not RSA
						Use: "sig",
						Kid: "ec-key",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		})
		testServer := httptest.NewServer(mux)
		defer testServer.Close()

		provider := &Provider{
			Issuer:     testServer.URL,
			JwksURI:    testServer.URL + "/jwks",
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		ctx := context.Background()
		_, err := provider.GetSigningKey(ctx, "")
		assert.ErrorIs(t, err, ErrNoSigningKey)
	})

	t.Run("skips keys with non-sig use", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
			jwks := JWKSet{
				Keys: []JWK{
					{
						Kty: "RSA",
						Use: "enc", // Encryption, not signing
						Kid: "enc-key",
						N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
						E:   "AQAB",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		})
		testServer := httptest.NewServer(mux)
		defer testServer.Close()

		provider := &Provider{
			Issuer:     testServer.URL,
			JwksURI:    testServer.URL + "/jwks",
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		ctx := context.Background()
		_, err := provider.GetSigningKey(ctx, "")
		assert.ErrorIs(t, err, ErrNoSigningKey)
	})

	t.Run("accepts keys with empty use", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
			jwks := JWKSet{
				Keys: []JWK{
					{
						Kty: "RSA",
						Use: "", // Empty use is acceptable for signing
						Kid: "key-empty-use",
						N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
						E:   "AQAB",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		})
		testServer := httptest.NewServer(mux)
		defer testServer.Close()

		provider := &Provider{
			Issuer:     testServer.URL,
			JwksURI:    testServer.URL + "/jwks",
			httpClient: &http.Client{Timeout: 5 * time.Second},
			jwksCache:  &JWKSCache{},
		}

		ctx := context.Background()
		key, err := provider.GetSigningKey(ctx, "")
		require.NoError(t, err)
		assert.NotNil(t, key)
	})
}

func TestParseRSAPublicKey_ErrorPaths(t *testing.T) {
	t.Run("fails with invalid N encoding", func(t *testing.T) {
		key := JWK{
			Kty: "RSA",
			N:   "!!!invalid-base64!!!",
			E:   "AQAB",
		}

		_, err := parseRSAPublicKey(key)
		assert.ErrorIs(t, err, ErrNoSigningKey)
	})

	t.Run("fails with invalid E encoding", func(t *testing.T) {
		key := JWK{
			Kty: "RSA",
			N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
			E:   "!!!invalid-base64!!!",
		}

		_, err := parseRSAPublicKey(key)
		assert.ErrorIs(t, err, ErrNoSigningKey)
	})

	t.Run("parses valid RSA key", func(t *testing.T) {
		key := JWK{
			Kty: "RSA",
			N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
			E:   "AQAB",
		}

		rsaKey, err := parseRSAPublicKey(key)
		require.NoError(t, err)
		assert.NotNil(t, rsaKey)
		assert.Equal(t, 65537, rsaKey.E)
	})
}

func TestProvider_SupportsScope(t *testing.T) {
	provider := &Provider{
		ScopesSupported: []string{"openid", "profile", "email"},
	}

	t.Run("returns true for supported scope", func(t *testing.T) {
		assert.True(t, provider.SupportsScope("openid"))
		assert.True(t, provider.SupportsScope("profile"))
		assert.True(t, provider.SupportsScope("email"))
	})

	t.Run("returns false for unsupported scope", func(t *testing.T) {
		assert.False(t, provider.SupportsScope("custom"))
	})
}

func TestProvider_SupportsPKCE(t *testing.T) {
	t.Run("returns true when S256 supported", func(t *testing.T) {
		provider := &Provider{
			CodeChallengeMethodsSupported: []string{"S256"},
		}
		assert.True(t, provider.SupportsPKCE())
	})

	t.Run("returns true when methods not listed", func(t *testing.T) {
		provider := &Provider{}
		assert.True(t, provider.SupportsPKCE())
	})

	t.Run("returns false when S256 not in list", func(t *testing.T) {
		provider := &Provider{
			CodeChallengeMethodsSupported: []string{"plain"},
		}
		assert.False(t, provider.SupportsPKCE())
	})
}

func TestProvider_SupportsSigningAlg(t *testing.T) {
	provider := &Provider{
		IDTokenSigningAlgValuesSupported: []string{"RS256", "RS384"},
	}

	t.Run("returns true for supported algorithm", func(t *testing.T) {
		assert.True(t, provider.SupportsSigningAlg("RS256"))
		assert.True(t, provider.SupportsSigningAlg("RS384"))
	})

	t.Run("returns false for unsupported algorithm", func(t *testing.T) {
		assert.False(t, provider.SupportsSigningAlg("ES256"))
	})
}

func TestProvider_IsInitialized(t *testing.T) {
	t.Run("returns true when all endpoints set", func(t *testing.T) {
		provider := &Provider{
			AuthorizationEndpoint: "https://example.com/authorize",
			TokenEndpoint:         "https://example.com/token",
			JwksURI:               "https://example.com/jwks",
		}
		assert.True(t, provider.IsInitialized())
	})

	t.Run("returns false when authorization endpoint missing", func(t *testing.T) {
		provider := &Provider{
			TokenEndpoint: "https://example.com/token",
			JwksURI:       "https://example.com/jwks",
		}
		assert.False(t, provider.IsInitialized())
	})

	t.Run("returns false when token endpoint missing", func(t *testing.T) {
		provider := &Provider{
			AuthorizationEndpoint: "https://example.com/authorize",
			JwksURI:               "https://example.com/jwks",
		}
		assert.False(t, provider.IsInitialized())
	})

	t.Run("returns false when JWKS URI missing", func(t *testing.T) {
		provider := &Provider{
			AuthorizationEndpoint: "https://example.com/authorize",
			TokenEndpoint:         "https://example.com/token",
		}
		assert.False(t, provider.IsInitialized())
	})
}

func TestNewProvider_ManualEndpoints(t *testing.T) {
	t.Run("skips discovery entirely when all required endpoints are set", func(t *testing.T) {
		// A discovery document is never served: any GET here fails the test,
		// proving NewProvider never dials .well-known/openid-configuration.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected discovery request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		config := &ProviderConfig{
			Issuer:                "https://manual.example.com",
			ClientID:              "client-123",
			RedirectURL:           "http://localhost:8080/callback",
			AuthorizationEndpoint: server.URL + "/authorize",
			TokenEndpoint:         server.URL + "/token",
			JwksURI:               server.URL + "/jwks",
			UserinfoEndpoint:      server.URL + "/userinfo",
		}

		provider, err := NewProvider(context.Background(), config)
		require.NoError(t, err)
		assert.True(t, provider.IsInitialized())
		assert.Equal(t, server.URL+"/authorize", provider.AuthorizationEndpoint)
		assert.Equal(t, server.URL+"/token", provider.TokenEndpoint)
		assert.Equal(t, server.URL+"/jwks", provider.JwksURI)
		assert.Equal(t, server.URL+"/userinfo", provider.UserinfoEndpoint)
	})

	t.Run("skips discovery without a userinfo endpoint", func(t *testing.T) {
		config := &ProviderConfig{
			Issuer:                "https://manual.example.com",
			ClientID:              "client-123",
			RedirectURL:           "http://localhost:8080/callback",
			AuthorizationEndpoint: "https://manual.example.com/authorize",
			TokenEndpoint:         "https://manual.example.com/token",
			JwksURI:               "https://manual.example.com/jwks",
		}

		provider, err := NewProvider(context.Background(), config)
		require.NoError(t, err)
		assert.True(t, provider.IsInitialized())
		assert.Empty(t, provider.UserinfoEndpoint)
	})

	t.Run("refuses partial manual endpoints naming what is missing", func(t *testing.T) {
		config := &ProviderConfig{
			Issuer:                "https://manual.example.com",
			ClientID:              "client-123",
			RedirectURL:           "http://localhost:8080/callback",
			AuthorizationEndpoint: "https://manual.example.com/authorize",
		}

		_, err := NewProvider(context.Background(), config)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrIncompleteManualEndpoints)
		assert.ErrorContains(t, err, "TokenEndpoint")
		assert.ErrorContains(t, err, "JwksURI")
		assert.NotContains(t, err.Error(), "AuthorizationEndpoint")
	})

	t.Run("bare SkipDiscovery with no manual endpoints still yields an uninitialized provider", func(t *testing.T) {
		config := &ProviderConfig{
			Issuer:        "https://manual.example.com",
			ClientID:      "client-123",
			RedirectURL:   "http://localhost:8080/callback",
			SkipDiscovery: true,
		}

		provider, err := NewProvider(context.Background(), config)
		require.NoError(t, err)
		assert.False(t, provider.IsInitialized())
	})
}

func TestProviderConfig_TokenEncoding(t *testing.T) {
	t.Run("empty encoding validates and defaults to form", func(t *testing.T) {
		config := &ProviderConfig{
			Issuer:      "https://auth.example.com",
			ClientID:    "client-123",
			RedirectURL: "http://localhost:8080/callback",
		}
		assert.NoError(t, config.Validate())
		assert.Equal(t, TokenEncodingForm, config.EffectiveTokenEncoding())
	})

	t.Run("json encoding is valid", func(t *testing.T) {
		config := &ProviderConfig{
			Issuer:        "https://auth.example.com",
			ClientID:      "client-123",
			RedirectURL:   "http://localhost:8080/callback",
			TokenEncoding: TokenEncodingJSON,
		}
		assert.NoError(t, config.Validate())
		assert.Equal(t, TokenEncodingJSON, config.EffectiveTokenEncoding())
	})

	t.Run("unknown encoding is refused", func(t *testing.T) {
		config := &ProviderConfig{
			Issuer:        "https://auth.example.com",
			ClientID:      "client-123",
			RedirectURL:   "http://localhost:8080/callback",
			TokenEncoding: TokenEncoding("xml"),
		}
		err := config.Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidTokenEncoding)
	})
}
