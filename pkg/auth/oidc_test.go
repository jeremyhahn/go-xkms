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

package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/metadata"
)

// mockOIDCProvider creates a mock OIDC provider server for testing.
type mockOIDCProvider struct {
	server       *httptest.Server
	privateKey   *ecdsa.PrivateKey
	publicKey    *ecdsa.PublicKey
	kid          string
	issuer       string
	userInfoData map[string]interface{}

	// validTokens tracks which tokens are valid for userinfo
	validTokens   map[string]bool
	validTokensMu sync.RWMutex
}

func newMockOIDCProvider(t *testing.T) *mockOIDCProvider {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	mock := &mockOIDCProvider{
		privateKey:  privateKey,
		publicKey:   &privateKey.PublicKey,
		kid:         "test-key-1",
		validTokens: make(map[string]bool),
		userInfoData: map[string]interface{}{
			"sub":                "user123",
			"email":              "user@example.com",
			"name":               "Test User",
			"preferred_username": "testuser",
		},
	}

	mux := http.NewServeMux()

	// Discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]interface{}{
			"issuer":                 mock.issuer,
			"authorization_endpoint": mock.issuer + "/authorize",
			"token_endpoint":         mock.issuer + "/token",
			"userinfo_endpoint":      mock.issuer + "/userinfo",
			"jwks_uri":               mock.issuer + "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	// JWKS endpoint
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{
			Key:       mock.publicKey,
			KeyID:     mock.kid,
			Algorithm: string(jose.ES256),
			Use:       "sig",
		}
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{jwk},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	// UserInfo endpoint - only accepts specifically registered tokens
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Check if this token is registered as valid
		mock.validTokensMu.RLock()
		valid := mock.validTokens[token]
		mock.validTokensMu.RUnlock()

		if !valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mock.userInfoData)
	})

	mock.server = httptest.NewServer(mux)
	mock.issuer = mock.server.URL

	return mock
}

func (m *mockOIDCProvider) close() {
	m.server.Close()
}

// registerValidAccessToken registers an opaque access token as valid for userinfo
func (m *mockOIDCProvider) registerValidAccessToken(token string) {
	m.validTokensMu.Lock()
	m.validTokens[token] = true
	m.validTokensMu.Unlock()
}

func (m *mockOIDCProvider) createIDToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()

	// Set default claims if not present
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = m.issuer
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = m.kid

	tokenString, err := token.SignedString(m.privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return tokenString
}

func TestNewOIDCAuthenticator(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	tests := []struct {
		name    string
		config  *OIDCConfig
		wantErr bool
		errType error
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errType: ErrOIDCConfigRequired,
		},
		{
			name: "empty issuer",
			config: &OIDCConfig{
				Issuer:   "",
				ClientID: "test-client",
			},
			wantErr: true,
			errType: ErrOIDCIssuerRequired,
		},
		{
			name: "empty client ID",
			config: &OIDCConfig{
				Issuer:   mock.issuer,
				ClientID: "",
			},
			wantErr: true,
			errType: ErrOIDCClientIDRequired,
		},
		{
			name: "valid config - minimal",
			config: &OIDCConfig{
				Issuer:   mock.issuer,
				ClientID: "test-client",
			},
			wantErr: false,
		},
		{
			name: "valid config - with audience",
			config: &OIDCConfig{
				Issuer:   mock.issuer,
				ClientID: "test-client",
				Audience: []string{"api.example.com"},
			},
			wantErr: false,
		},
		{
			name: "valid config - with custom TTL",
			config: &OIDCConfig{
				Issuer:       mock.issuer,
				ClientID:     "test-client",
				JWKSCacheTTL: 30 * time.Minute,
			},
			wantErr: false,
		},
		{
			name: "invalid issuer - discovery fails",
			config: &OIDCConfig{
				Issuer:   "http://invalid.example.com:12345",
				ClientID: "test-client",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			auth, err := NewOIDCAuthenticator(ctx, tt.config)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if tt.errType != nil {
					if oidcErr, ok := err.(*OIDCAuthenticatorError); ok {
						if oidcErr.Message != tt.errType.(*OIDCAuthenticatorError).Message {
							t.Errorf("error = %v, want %v", oidcErr.Message, tt.errType.(*OIDCAuthenticatorError).Message)
						}
					}
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if auth == nil {
				t.Error("expected non-nil authenticator")
			}
		})
	}
}

func TestOIDCAuthenticator_AuthenticateHTTP(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	tests := []struct {
		name        string
		setupReq    func(*http.Request, *mockOIDCProvider)
		wantErr     bool
		wantSubject string
		checkAttrs  map[string]string
	}{
		{
			name: "valid ID token",
			setupReq: func(req *http.Request, m *mockOIDCProvider) {
				token := m.createIDToken(t, jwt.MapClaims{
					"sub":                "user123",
					"aud":                "test-client",
					"email":              "user@example.com",
					"name":               "Test User",
					"preferred_username": "testuser",
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr:     false,
			wantSubject: "user123",
			checkAttrs: map[string]string{
				"auth_method":  "oidc",
				"email":        "user@example.com",
				"display_name": "Test User",
				"username":     "testuser",
			},
		},
		{
			name: "valid ID token without Bearer prefix",
			setupReq: func(req *http.Request, m *mockOIDCProvider) {
				token := m.createIDToken(t, jwt.MapClaims{
					"sub": "user456",
					"aud": "test-client",
				})
				req.Header.Set("Authorization", token)
			},
			wantErr:     false,
			wantSubject: "user456",
		},
		{
			name: "no authorization header",
			setupReq: func(req *http.Request, m *mockOIDCProvider) {
				// No header set
			},
			wantErr: true,
		},
		{
			name: "empty Bearer token",
			setupReq: func(req *http.Request, m *mockOIDCProvider) {
				req.Header.Set("Authorization", "Bearer ")
			},
			wantErr: true,
		},
		{
			name: "expired token",
			setupReq: func(req *http.Request, m *mockOIDCProvider) {
				token := m.createIDToken(t, jwt.MapClaims{
					"sub": "user123",
					"aud": "test-client",
					"exp": time.Now().Add(-time.Hour).Unix(), // Expired
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr: true,
		},
		{
			name: "wrong audience",
			setupReq: func(req *http.Request, m *mockOIDCProvider) {
				token := m.createIDToken(t, jwt.MapClaims{
					"sub": "user123",
					"aud": "wrong-client",
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr: true,
		},
		{
			name: "wrong issuer",
			setupReq: func(req *http.Request, m *mockOIDCProvider) {
				token := m.createIDToken(t, jwt.MapClaims{
					"sub": "user123",
					"aud": "test-client",
					"iss": "https://wrong-issuer.example.com",
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr: true,
		},
		{
			name: "valid access token via userinfo",
			setupReq: func(req *http.Request, m *mockOIDCProvider) {
				// Register an opaque access token as valid
				opaqueToken := "opaque-access-token-12345"
				m.registerValidAccessToken(opaqueToken)
				req.Header.Set("Authorization", "Bearer "+opaqueToken)
			},
			wantErr:     false,
			wantSubject: "user123", // from userInfoData
		},
		{
			name: "token with roles claim",
			setupReq: func(req *http.Request, m *mockOIDCProvider) {
				token := m.createIDToken(t, jwt.MapClaims{
					"sub":   "user123",
					"aud":   "test-client",
					"roles": []interface{}{"admin", "user"},
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr:     false,
			wantSubject: "user123",
		},
		{
			name: "token with groups claim",
			setupReq: func(req *http.Request, m *mockOIDCProvider) {
				token := m.createIDToken(t, jwt.MapClaims{
					"sub":    "user123",
					"aud":    "test-client",
					"groups": []interface{}{"developers", "admins"},
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr:     false,
			wantSubject: "user123",
		},
		{
			name: "token with keycloak realm_access",
			setupReq: func(req *http.Request, m *mockOIDCProvider) {
				token := m.createIDToken(t, jwt.MapClaims{
					"sub": "user123",
					"aud": "test-client",
					"realm_access": map[string]interface{}{
						"roles": []interface{}{"realm_admin", "realm_user"},
					},
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr:     false,
			wantSubject: "user123",
		},
		{
			name: "token with array audience",
			setupReq: func(req *http.Request, m *mockOIDCProvider) {
				token := m.createIDToken(t, jwt.MapClaims{
					"sub": "user123",
					"aud": []interface{}{"other-client", "test-client"},
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr:     false,
			wantSubject: "user123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
				Issuer:   mock.issuer,
				ClientID: "test-client",
			})
			if err != nil {
				t.Fatalf("failed to create authenticator: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			tt.setupReq(req, mock)

			identity, err := auth.AuthenticateHTTP(req)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if identity == nil {
				t.Fatal("expected identity, got nil")
			}
			if identity.Subject != tt.wantSubject {
				t.Errorf("Subject = %v, want %v", identity.Subject, tt.wantSubject)
			}

			// Check attributes if specified
			for key, want := range tt.checkAttrs {
				if got := identity.Attributes[key]; got != want {
					t.Errorf("Attribute[%s] = %v, want %v", key, got, want)
				}
			}
		})
	}
}

func TestOIDCAuthenticator_AuthenticateGRPC(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	tests := []struct {
		name        string
		setupMD     func(metadata.MD, *mockOIDCProvider)
		wantErr     bool
		wantSubject string
	}{
		{
			name: "valid bearer token in authorization",
			setupMD: func(md metadata.MD, m *mockOIDCProvider) {
				token := m.createIDToken(t, jwt.MapClaims{
					"sub": "grpc-user",
					"aud": "test-client",
				})
				md.Set("authorization", "Bearer "+token)
			},
			wantErr:     false,
			wantSubject: "grpc-user",
		},
		{
			name: "valid token without Bearer prefix in metadata",
			setupMD: func(md metadata.MD, m *mockOIDCProvider) {
				token := m.createIDToken(t, jwt.MapClaims{
					"sub": "grpc-user2",
					"aud": "test-client",
				})
				md.Set("authorization", token)
			},
			wantErr:     false,
			wantSubject: "grpc-user2",
		},
		{
			name: "no token in metadata",
			setupMD: func(md metadata.MD, m *mockOIDCProvider) {
				// No token set
			},
			wantErr: true,
		},
		{
			name: "expired token in metadata",
			setupMD: func(md metadata.MD, m *mockOIDCProvider) {
				token := m.createIDToken(t, jwt.MapClaims{
					"sub": "grpc-user",
					"aud": "test-client",
					"exp": time.Now().Add(-time.Hour).Unix(),
				})
				md.Set("authorization", "Bearer "+token)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
				Issuer:   mock.issuer,
				ClientID: "test-client",
			})
			if err != nil {
				t.Fatalf("failed to create authenticator: %v", err)
			}

			md := metadata.MD{}
			tt.setupMD(md, mock)

			identity, err := auth.AuthenticateGRPC(ctx, md)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if identity == nil {
				t.Fatal("expected identity, got nil")
			}
			if identity.Subject != tt.wantSubject {
				t.Errorf("Subject = %v, want %v", identity.Subject, tt.wantSubject)
			}
			if identity.Attributes["auth_method"] != "oidc" {
				t.Errorf("auth_method = %v, want oidc", identity.Attributes["auth_method"])
			}
		})
	}
}

func TestOIDCAuthenticator_Name(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   mock.issuer,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	name := auth.Name()
	if name != "oidc" {
		t.Errorf("Name() = %v, want oidc", name)
	}
}

func TestOIDCAuthenticator_JWKSCache(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:       mock.issuer,
		ClientID:     "test-client",
		JWKSCacheTTL: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// First request should populate cache
	token := mock.createIDToken(t, jwt.MapClaims{
		"sub": "user1",
		"aud": "test-client",
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err = auth.AuthenticateHTTP(req)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}

	// Second request should use cache
	token2 := mock.createIDToken(t, jwt.MapClaims{
		"sub": "user2",
		"aud": "test-client",
	})
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", "Bearer "+token2)

	identity, err := auth.AuthenticateHTTP(req2)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	if identity.Subject != "user2" {
		t.Errorf("Subject = %v, want user2", identity.Subject)
	}

	// Wait for cache to expire
	time.Sleep(150 * time.Millisecond)

	// Third request should refresh cache
	token3 := mock.createIDToken(t, jwt.MapClaims{
		"sub": "user3",
		"aud": "test-client",
	})
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.Header.Set("Authorization", "Bearer "+token3)

	identity3, err := auth.AuthenticateHTTP(req3)
	if err != nil {
		t.Fatalf("third request failed: %v", err)
	}
	if identity3.Subject != "user3" {
		t.Errorf("Subject = %v, want user3", identity3.Subject)
	}
}

func TestOIDCAuthenticator_RoleExtraction(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	tests := []struct {
		name      string
		claims    jwt.MapClaims
		wantRoles []string
	}{
		{
			name: "roles claim as array",
			claims: jwt.MapClaims{
				"sub":   "user1",
				"aud":   "test-client",
				"roles": []interface{}{"admin", "user"},
			},
			wantRoles: []string{"admin", "user"},
		},
		{
			name: "groups claim as array",
			claims: jwt.MapClaims{
				"sub":    "user1",
				"aud":    "test-client",
				"groups": []interface{}{"developers", "admins"},
			},
			wantRoles: []string{"developers", "admins"},
		},
		{
			name: "keycloak realm_access roles",
			claims: jwt.MapClaims{
				"sub": "user1",
				"aud": "test-client",
				"realm_access": map[string]interface{}{
					"roles": []interface{}{"realm_admin"},
				},
			},
			wantRoles: []string{"realm_admin"},
		},
		{
			name: "keycloak resource_access roles",
			claims: jwt.MapClaims{
				"sub": "user1",
				"aud": "test-client",
				"resource_access": map[string]interface{}{
					"my-client": map[string]interface{}{
						"roles": []interface{}{"client_role"},
					},
				},
			},
			wantRoles: []string{"client_role"},
		},
		{
			name: "combined roles from multiple sources",
			claims: jwt.MapClaims{
				"sub":    "user1",
				"aud":    "test-client",
				"roles":  []interface{}{"standard_role"},
				"groups": []interface{}{"group1"},
			},
			wantRoles: []string{"standard_role", "group1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
				Issuer:   mock.issuer,
				ClientID: "test-client",
			})
			if err != nil {
				t.Fatalf("failed to create authenticator: %v", err)
			}

			token := mock.createIDToken(t, tt.claims)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+token)

			identity, err := auth.AuthenticateHTTP(req)
			if err != nil {
				t.Fatalf("AuthenticateHTTP() error = %v", err)
			}

			// Check roles
			roles, ok := identity.Claims["roles"].([]string)
			if !ok {
				t.Fatalf("roles not found or wrong type")
			}

			if len(roles) != len(tt.wantRoles) {
				t.Errorf("roles count = %d, want %d", len(roles), len(tt.wantRoles))
			}

			for _, wantRole := range tt.wantRoles {
				found := false
				for _, role := range roles {
					if role == wantRole {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("role %s not found in %v", wantRole, roles)
				}
			}
		})
	}
}

func TestOIDCAuthenticator_InvalidToken(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   mock.issuer,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{
			name:    "malformed token",
			token:   "not.a.valid.jwt.token",
			wantErr: true,
		},
		{
			name:    "completely invalid",
			token:   "invalid-token",
			wantErr: true,
		},
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.token == "" {
				req.Header.Set("Authorization", "Bearer ")
			} else {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			_, err := auth.AuthenticateHTTP(req)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestOIDCAuthenticator_SkipValidation(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()

	t.Run("skip issuer check", func(t *testing.T) {
		auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
			Issuer:          mock.issuer,
			ClientID:        "test-client",
			SkipIssuerCheck: true,
		})
		if err != nil {
			t.Fatalf("failed to create authenticator: %v", err)
		}

		token := mock.createIDToken(t, jwt.MapClaims{
			"sub": "user123",
			"aud": "test-client",
			"iss": "https://different-issuer.example.com",
		})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		identity, err := auth.AuthenticateHTTP(req)
		if err != nil {
			t.Errorf("expected no error with skip issuer check, got: %v", err)
			return
		}
		if identity.Subject != "user123" {
			t.Errorf("Subject = %v, want user123", identity.Subject)
		}
	})

	t.Run("skip client ID check", func(t *testing.T) {
		auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
			Issuer:            mock.issuer,
			ClientID:          "test-client",
			SkipClientIDCheck: true,
		})
		if err != nil {
			t.Fatalf("failed to create authenticator: %v", err)
		}

		token := mock.createIDToken(t, jwt.MapClaims{
			"sub": "user123",
			"aud": "different-client",
		})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		identity, err := auth.AuthenticateHTTP(req)
		if err != nil {
			t.Errorf("expected no error with skip client ID check, got: %v", err)
			return
		}
		if identity.Subject != "user123" {
			t.Errorf("Subject = %v, want user123", identity.Subject)
		}
	})
}

func TestOIDCAuthenticator_CustomAudience(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   mock.issuer,
		ClientID: "test-client",
		Audience: []string{"api.example.com", "web.example.com"},
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	tests := []struct {
		name    string
		aud     interface{}
		wantErr bool
	}{
		{
			name:    "matching string audience",
			aud:     "api.example.com",
			wantErr: false,
		},
		{
			name:    "matching second audience",
			aud:     "web.example.com",
			wantErr: false,
		},
		{
			name:    "non-matching audience",
			aud:     "other.example.com",
			wantErr: true,
		},
		{
			name:    "array with one matching",
			aud:     []interface{}{"other.example.com", "api.example.com"},
			wantErr: false,
		},
		{
			name:    "array with no matching",
			aud:     []interface{}{"other1.example.com", "other2.example.com"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := mock.createIDToken(t, jwt.MapClaims{
				"sub": "user123",
				"aud": tt.aud,
			})
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+token)

			_, err := auth.AuthenticateHTTP(req)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestOIDCAuthenticator_WrongSigningKey(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   mock.issuer,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Generate a different key for signing
	differentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create token with different key but same kid
	claims := jwt.MapClaims{
		"sub": "user123",
		"aud": "test-client",
		"iss": mock.issuer,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = mock.kid

	tokenString, err := token.SignedString(differentKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	_, err = auth.AuthenticateHTTP(req)
	if err == nil {
		t.Error("expected error for token signed with different key")
	}
}

func TestOIDCAuthenticator_MissingKid(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   mock.issuer,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Create token without kid header
	claims := jwt.MapClaims{
		"sub": "user123",
		"aud": "test-client",
		"iss": mock.issuer,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	// Note: not setting token.Header["kid"]

	tokenString, err := token.SignedString(mock.privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	_, err = auth.AuthenticateHTTP(req)
	if err == nil {
		t.Error("expected error for token without kid")
	}
}

func TestOIDCAuthenticator_UnknownKid(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   mock.issuer,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Create token with unknown kid
	claims := jwt.MapClaims{
		"sub": "user123",
		"aud": "test-client",
		"iss": mock.issuer,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "unknown-kid"

	tokenString, err := token.SignedString(mock.privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	_, err = auth.AuthenticateHTTP(req)
	if err == nil {
		t.Error("expected error for token with unknown kid")
	}
}

func TestOIDCAuthenticatorError(t *testing.T) {
	t.Run("error without cause", func(t *testing.T) {
		err := &OIDCAuthenticatorError{Message: "test error"}
		if err.Error() != "test error" {
			t.Errorf("Error() = %v, want test error", err.Error())
		}
		if err.Unwrap() != nil {
			t.Error("expected nil unwrap")
		}
	})

	t.Run("error with cause", func(t *testing.T) {
		cause := &OIDCAuthenticatorError{Message: "cause error"}
		err := &OIDCAuthenticatorError{Message: "test error", Cause: cause}
		if err.Error() != "test error: cause error" {
			t.Errorf("Error() = %v, want test error: cause error", err.Error())
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() did not return cause")
		}
	})
}

func TestExtractStringSlice(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  []string
	}{
		{
			name:  "string slice",
			input: []string{"a", "b", "c"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "interface slice",
			input: []interface{}{"x", "y", "z"},
			want:  []string{"x", "y", "z"},
		},
		{
			name:  "single string",
			input: "single",
			want:  []string{"single"},
		},
		{
			name:  "nil",
			input: nil,
			want:  nil,
		},
		{
			name:  "mixed interface slice",
			input: []interface{}{"a", 123, "b"},
			want:  []string{"a", "b"},
		},
		{
			name:  "unsupported type",
			input: 123,
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractStringSlice(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("extractStringSlice() len = %d, want %d", len(got), len(tt.want))
				return
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("extractStringSlice()[%d] = %v, want %v", i, v, tt.want[i])
				}
			}
		})
	}
}

func TestOIDCAuthenticator_ImplementsInterface(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   mock.issuer,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Verify it implements the Authenticator interface
	var _ Authenticator = auth
}

func TestOIDCAuthenticator_AccessTokenFallback(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   mock.issuer,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	t.Run("valid opaque access token", func(t *testing.T) {
		opaqueToken := "valid-opaque-token-xyz"
		mock.registerValidAccessToken(opaqueToken)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+opaqueToken)

		identity, err := auth.AuthenticateHTTP(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if identity.Subject != "user123" {
			t.Errorf("Subject = %v, want user123", identity.Subject)
		}
	})

	t.Run("invalid opaque access token", func(t *testing.T) {
		// This token is not registered, should fail
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer unregistered-token")

		_, err := auth.AuthenticateHTTP(req)
		if err == nil {
			t.Error("expected error for unregistered access token")
		}
	})
}

func TestOIDCAuthenticator_ConcurrentAccess(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:       mock.issuer,
		ClientID:     "test-client",
		JWKSCacheTTL: 50 * time.Millisecond, // Short TTL to test cache refresh
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	// Run concurrent requests
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			token := mock.createIDToken(t, jwt.MapClaims{
				"sub": "user" + string(rune('0'+idx%10)),
				"aud": "test-client",
			})
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+token)

			_, err := auth.AuthenticateHTTP(req)
			if err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent request failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// discover() error path tests
// ---------------------------------------------------------------------------

func TestOIDCAuthenticator_Discover_NonOKStatus(t *testing.T) {
	// Create a server that returns non-200 on the discovery endpoint.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   server.URL,
		ClientID: "test-client",
	})
	if err == nil {
		t.Fatal("expected error for non-200 discovery response")
	}
	oidcErr, ok := err.(*OIDCAuthenticatorError)
	if !ok {
		t.Fatalf("expected *OIDCAuthenticatorError, got %T", err)
	}
	if oidcErr.Message != ErrOIDCDiscoveryFailed.Message {
		t.Errorf("error message = %q, want %q", oidcErr.Message, ErrOIDCDiscoveryFailed.Message)
	}
}

func TestOIDCAuthenticator_Discover_InvalidJSON(t *testing.T) {
	// Create a server that returns 200 but invalid JSON on discovery.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json {{{"))
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   server.URL,
		ClientID: "test-client",
	})
	if err == nil {
		t.Fatal("expected error for invalid JSON discovery response")
	}
	oidcErr, ok := err.(*OIDCAuthenticatorError)
	if !ok {
		t.Fatalf("expected *OIDCAuthenticatorError, got %T", err)
	}
	if oidcErr.Message != "failed to parse discovery document" {
		t.Errorf("error message = %q, want %q", oidcErr.Message, "failed to parse discovery document")
	}
}

func TestOIDCAuthenticator_Discover_InvalidURL(t *testing.T) {
	// Use a URL with control characters to trigger NewRequestWithContext failure.
	// The issuer URL with a control character will cause http.NewRequestWithContext to fail.
	ctx := context.Background()
	_, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   "http://example.com\x7f",
		ClientID: "test-client",
	})
	if err == nil {
		t.Fatal("expected error for invalid URL with control character")
	}
	oidcErr, ok := err.(*OIDCAuthenticatorError)
	if !ok {
		t.Fatalf("expected *OIDCAuthenticatorError, got %T", err)
	}
	if oidcErr.Message != "failed to create discovery request" {
		t.Errorf("error message = %q, want %q", oidcErr.Message, "failed to create discovery request")
	}
}

// ---------------------------------------------------------------------------
// getJWKS() error path tests
// ---------------------------------------------------------------------------

func TestOIDCAuthenticator_GetJWKS_NilDiscovery(t *testing.T) {
	// Create a valid mock provider for initial discovery, then clear discovery.
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:       mock.issuer,
		ClientID:     "test-client",
		JWKSCacheTTL: 1 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Clear the discovery document to simulate nil discovery.
	auth.discovery.Store(nil)

	// Attempt a request which requires fetching JWKS.
	token := mock.createIDToken(t, jwt.MapClaims{
		"sub": "user123",
		"aud": "test-client",
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err = auth.AuthenticateHTTP(req)
	if err == nil {
		t.Fatal("expected error when discovery is nil")
	}
}

func TestOIDCAuthenticator_GetJWKS_EmptyJWKSUri(t *testing.T) {
	// Create a mock provider, then overwrite discovery with empty JWKS URI.
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:       mock.issuer,
		ClientID:     "test-client",
		JWKSCacheTTL: 1 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Replace discovery with a document that has no JWKS URI.
	auth.discovery.Store(&oidcDiscoveryDocument{
		Issuer:           mock.issuer,
		JWKSUri:          "",
		UserInfoEndpoint: mock.issuer + "/userinfo",
	})

	// Force cache to be expired so getJWKS must re-fetch.
	auth.jwksCache.mu.Lock()
	auth.jwksCache.keys = nil
	auth.jwksCache.expiresAt = time.Time{}
	auth.jwksCache.mu.Unlock()

	token := mock.createIDToken(t, jwt.MapClaims{
		"sub": "user123",
		"aud": "test-client",
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err = auth.AuthenticateHTTP(req)
	if err == nil {
		t.Fatal("expected error when JWKS URI is empty")
	}
}

func TestOIDCAuthenticator_GetJWKS_NonOKStatus(t *testing.T) {
	// Create a mock OIDC provider that returns 500 on the JWKS endpoint.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	var serverURL string
	mux := http.NewServeMux()

	// Discovery returns a valid document
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]interface{}{
			"issuer":                 serverURL,
			"authorization_endpoint": serverURL + "/authorize",
			"token_endpoint":         serverURL + "/token",
			"userinfo_endpoint":      serverURL + "/userinfo",
			"jwks_uri":               serverURL + "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	// JWKS endpoint returns 500
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	ctx := context.Background()
	auth, authErr := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   serverURL,
		ClientID: "test-client",
	})
	if authErr != nil {
		t.Fatalf("failed to create authenticator: %v", authErr)
	}

	// Create a token (even though JWKS fetch will fail).
	claims := jwt.MapClaims{
		"sub": "user123",
		"aud": "test-client",
		"iss": serverURL,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key-1"
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	_, err = auth.AuthenticateHTTP(req)
	if err == nil {
		t.Fatal("expected error when JWKS endpoint returns 500")
	}
}

func TestOIDCAuthenticator_GetJWKS_InvalidJSON(t *testing.T) {
	// Create a mock provider with a JWKS endpoint that returns invalid JSON.
	var serverURL string
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]interface{}{
			"issuer":                 serverURL,
			"authorization_endpoint": serverURL + "/authorize",
			"token_endpoint":         serverURL + "/token",
			"userinfo_endpoint":      serverURL + "/userinfo",
			"jwks_uri":               serverURL + "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	// JWKS endpoint returns invalid JSON
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json {{{"))
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	ctx := context.Background()
	auth, authErr := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   serverURL,
		ClientID: "test-client",
	})
	if authErr != nil {
		t.Fatalf("failed to create authenticator: %v", authErr)
	}

	claims := jwt.MapClaims{
		"sub": "user123",
		"aud": "test-client",
		"iss": serverURL,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key-1"
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	_, err = auth.AuthenticateHTTP(req)
	if err == nil {
		t.Fatal("expected error when JWKS endpoint returns invalid JSON")
	}
}

func TestOIDCAuthenticator_GetJWKS_ConnectionError(t *testing.T) {
	// Create a mock provider, then point the JWKS URI to a closed server.
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:       mock.issuer,
		ClientID:     "test-client",
		JWKSCacheTTL: 1 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Create a temporary server and immediately close it to get an unreachable URL.
	closedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := closedServer.URL
	closedServer.Close()

	// Replace discovery with a document pointing JWKS URI to the closed server.
	auth.discovery.Store(&oidcDiscoveryDocument{
		Issuer:           mock.issuer,
		JWKSUri:          closedURL + "/jwks",
		UserInfoEndpoint: mock.issuer + "/userinfo",
	})

	// Force cache expiry.
	auth.jwksCache.mu.Lock()
	auth.jwksCache.keys = nil
	auth.jwksCache.expiresAt = time.Time{}
	auth.jwksCache.mu.Unlock()

	token := mock.createIDToken(t, jwt.MapClaims{
		"sub": "user123",
		"aud": "test-client",
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err = auth.AuthenticateHTTP(req)
	if err == nil {
		t.Fatal("expected error when JWKS endpoint is unreachable")
	}
}

func TestOIDCAuthenticator_GetJWKS_InvalidJWKSUrl(t *testing.T) {
	// Test with a JWKS URI that contains control characters to trigger
	// http.NewRequestWithContext failure.
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:       mock.issuer,
		ClientID:     "test-client",
		JWKSCacheTTL: 1 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Replace discovery with a document containing an invalid JWKS URI.
	auth.discovery.Store(&oidcDiscoveryDocument{
		Issuer:           mock.issuer,
		JWKSUri:          "http://example.com\x7f/jwks",
		UserInfoEndpoint: mock.issuer + "/userinfo",
	})

	// Force cache expiry.
	auth.jwksCache.mu.Lock()
	auth.jwksCache.keys = nil
	auth.jwksCache.expiresAt = time.Time{}
	auth.jwksCache.mu.Unlock()

	token := mock.createIDToken(t, jwt.MapClaims{
		"sub": "user123",
		"aud": "test-client",
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err = auth.AuthenticateHTTP(req)
	if err == nil {
		t.Fatal("expected error when JWKS URI is invalid")
	}
}

// ---------------------------------------------------------------------------
// validateAccessToken() error path tests
// ---------------------------------------------------------------------------

func TestOIDCAuthenticator_ValidateAccessToken_NoUserInfoEndpoint(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   mock.issuer,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Replace discovery with document that has no userinfo endpoint.
	auth.discovery.Store(&oidcDiscoveryDocument{
		Issuer:  mock.issuer,
		JWKSUri: mock.issuer + "/jwks",
		// UserInfoEndpoint is deliberately empty.
	})

	// Use an opaque token that will fail JWT validation and fall back
	// to access token validation via userinfo.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer opaque-no-userinfo-token")

	_, err = auth.AuthenticateHTTP(req)
	if err == nil {
		t.Fatal("expected error when userinfo endpoint is empty")
	}
	oidcErr, ok := err.(*OIDCAuthenticatorError)
	if !ok {
		t.Fatalf("expected *OIDCAuthenticatorError, got %T", err)
	}
	if oidcErr.Message != "userinfo endpoint not available" {
		t.Errorf("error message = %q, want %q", oidcErr.Message, "userinfo endpoint not available")
	}
}

func TestOIDCAuthenticator_ValidateAccessToken_NonOKUserInfo(t *testing.T) {
	// Create a custom server where userinfo always returns 403.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	var serverURL string
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]interface{}{
			"issuer":                 serverURL,
			"authorization_endpoint": serverURL + "/authorize",
			"token_endpoint":         serverURL + "/token",
			"userinfo_endpoint":      serverURL + "/userinfo",
			"jwks_uri":               serverURL + "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{
			Key:       &privateKey.PublicKey,
			KeyID:     "test-key-1",
			Algorithm: string(jose.ES256),
			Use:       "sig",
		}
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	// Userinfo always returns 403 Forbidden.
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	ctx := context.Background()
	auth, authErr := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   serverURL,
		ClientID: "test-client",
	})
	if authErr != nil {
		t.Fatalf("failed to create authenticator: %v", authErr)
	}

	// Use an opaque token so JWT validation fails, triggering access token path.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer opaque-forbidden-token")

	_, err = auth.AuthenticateHTTP(req)
	if err == nil {
		t.Fatal("expected error when userinfo returns 403")
	}
}

func TestOIDCAuthenticator_ValidateAccessToken_InvalidJSONUserInfo(t *testing.T) {
	// Create a custom server where userinfo returns invalid JSON.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	var serverURL string
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]interface{}{
			"issuer":                 serverURL,
			"authorization_endpoint": serverURL + "/authorize",
			"token_endpoint":         serverURL + "/token",
			"userinfo_endpoint":      serverURL + "/userinfo",
			"jwks_uri":               serverURL + "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{
			Key:       &privateKey.PublicKey,
			KeyID:     "test-key-1",
			Algorithm: string(jose.ES256),
			Use:       "sig",
		}
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	// Userinfo returns 200 but invalid JSON body.
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json {{{"))
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	ctx := context.Background()
	auth, authErr := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   serverURL,
		ClientID: "test-client",
	})
	if authErr != nil {
		t.Fatalf("failed to create authenticator: %v", authErr)
	}

	// Use an opaque token so JWT validation fails, triggering access token path.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer opaque-bad-json-token")

	_, err = auth.AuthenticateHTTP(req)
	if err == nil {
		t.Fatal("expected error when userinfo returns invalid JSON")
	}
	oidcErr, ok := err.(*OIDCAuthenticatorError)
	if !ok {
		t.Fatalf("expected *OIDCAuthenticatorError, got %T", err)
	}
	if oidcErr.Message != "failed to parse userinfo response" {
		t.Errorf("error message = %q, want %q", oidcErr.Message, "failed to parse userinfo response")
	}
}

func TestOIDCAuthenticator_ValidateAccessToken_ConnectionError(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   mock.issuer,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Create a temporary server and close it to get an unreachable URL.
	closedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := closedServer.URL
	closedServer.Close()

	// Replace discovery with a document pointing userinfo to closed server.
	auth.discovery.Store(&oidcDiscoveryDocument{
		Issuer:           mock.issuer,
		JWKSUri:          mock.issuer + "/jwks",
		UserInfoEndpoint: closedURL + "/userinfo",
	})

	// Use an opaque token so JWT validation fails, triggering access token path.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer opaque-conn-error-token")

	_, err = auth.AuthenticateHTTP(req)
	if err == nil {
		t.Fatal("expected error when userinfo endpoint is unreachable")
	}
}

func TestOIDCAuthenticator_ValidateAccessToken_InvalidUserInfoUrl(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   mock.issuer,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Replace discovery with document containing an invalid userinfo URL.
	auth.discovery.Store(&oidcDiscoveryDocument{
		Issuer:           mock.issuer,
		JWKSUri:          mock.issuer + "/jwks",
		UserInfoEndpoint: "http://example.com\x7f/userinfo",
	})

	// Use an opaque token so JWT validation fails, triggering access token path.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer opaque-invalid-url-token")

	_, err = auth.AuthenticateHTTP(req)
	if err == nil {
		t.Fatal("expected error when userinfo URL is invalid")
	}
}

// ---------------------------------------------------------------------------
// validateAudience() edge case tests
// ---------------------------------------------------------------------------

func TestOIDCAuthenticator_ValidateAudience_InvalidFormat(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   mock.issuer,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Directly test validateAudience with an invalid type (integer).
	claims := jwt.MapClaims{
		"aud": 12345,
	}
	err = auth.validateAudience(claims)
	if err == nil {
		t.Fatal("expected error for integer audience format")
	}
	oidcErr, ok := err.(*OIDCAuthenticatorError)
	if !ok {
		t.Fatalf("expected *OIDCAuthenticatorError, got %T", err)
	}
	if oidcErr.Message != "invalid audience format" {
		t.Errorf("error message = %q, want %q", oidcErr.Message, "invalid audience format")
	}
}

func TestOIDCAuthenticator_ValidateAudience_NilAudience(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   mock.issuer,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// No aud claim at all.
	claims := jwt.MapClaims{}
	err = auth.validateAudience(claims)
	if err == nil {
		t.Fatal("expected error for nil audience")
	}
}

func TestOIDCAuthenticator_ValidateAudience_ArrayNoMatch(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   mock.issuer,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Array audience with no matching entries.
	claims := jwt.MapClaims{
		"aud": []interface{}{"other-client-1", "other-client-2"},
	}
	err = auth.validateAudience(claims)
	if err == nil {
		t.Fatal("expected error for non-matching array audience")
	}
	oidcErr, ok := err.(*OIDCAuthenticatorError)
	if !ok {
		t.Fatalf("expected *OIDCAuthenticatorError, got %T", err)
	}
	if oidcErr.Message != ErrOIDCInvalidAudience.Message {
		t.Errorf("error message = %q, want %q", oidcErr.Message, ErrOIDCInvalidAudience.Message)
	}
}

func TestOIDCAuthenticator_ValidateAudience_ArrayWithNonStringItems(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   mock.issuer,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Array audience where items are non-strings (integers).
	claims := jwt.MapClaims{
		"aud": []interface{}{123, 456},
	}
	err = auth.validateAudience(claims)
	if err == nil {
		t.Fatal("expected error for array audience with non-string items")
	}
}

// ---------------------------------------------------------------------------
// validateAccessToken() with nil discovery
// ---------------------------------------------------------------------------

func TestOIDCAuthenticator_ValidateAccessToken_NilDiscovery(t *testing.T) {
	mock := newMockOIDCProvider(t)
	defer mock.close()

	ctx := context.Background()
	auth, err := NewOIDCAuthenticator(ctx, &OIDCConfig{
		Issuer:   mock.issuer,
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Clear discovery entirely.
	auth.discovery.Store(nil)
	// Clear JWKS cache to force re-fetch attempt.
	auth.jwksCache.mu.Lock()
	auth.jwksCache.keys = nil
	auth.jwksCache.expiresAt = time.Time{}
	auth.jwksCache.mu.Unlock()

	// Use an opaque token (not a JWT) so it falls through to access token validation.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer opaque-nil-discovery-token")

	_, err = auth.AuthenticateHTTP(req)
	if err == nil {
		t.Fatal("expected error when discovery is nil")
	}
}
