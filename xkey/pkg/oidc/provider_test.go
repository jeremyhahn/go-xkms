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

	// Discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		metadata := map[string]interface{}{
			"issuer":                                "ISSUER_PLACEHOLDER",
			"authorization_endpoint":                "ISSUER_PLACEHOLDER/authorize",
			"token_endpoint":                        "ISSUER_PLACEHOLDER/token",
			"userinfo_endpoint":                     "ISSUER_PLACEHOLDER/userinfo",
			"jwks_uri":                              "ISSUER_PLACEHOLDER/jwks",
			"registration_endpoint":                 "ISSUER_PLACEHOLDER/register",
			"revocation_endpoint":                   "ISSUER_PLACEHOLDER/revoke",
			"end_session_endpoint":                  "ISSUER_PLACEHOLDER/logout",
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
