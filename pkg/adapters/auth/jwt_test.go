// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/metadata"
)

func generateTestKeyPair(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

func createTestToken(t *testing.T, privateKey *ecdsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return tokenString
}

func TestNewJWTAuthenticator(t *testing.T) {
	_, publicKey := generateTestKeyPair(t)

	tests := []struct {
		name    string
		config  *JWTConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "config is required",
		},
		{
			name: "nil public key",
			config: &JWTConfig{
				PublicKey: nil,
			},
			wantErr: true,
			errMsg:  "public key is required",
		},
		{
			name: "valid config - minimal",
			config: &JWTConfig{
				PublicKey: publicKey,
			},
			wantErr: false,
		},
		{
			name: "valid config - with issuer",
			config: &JWTConfig{
				PublicKey: publicKey,
				Issuer:    "https://auth.example.com",
			},
			wantErr: false,
		},
		{
			name: "valid config - with audience",
			config: &JWTConfig{
				PublicKey: publicKey,
				Audience:  []string{"api.example.com"},
			},
			wantErr: false,
		},
		{
			name: "valid config - with custom header",
			config: &JWTConfig{
				PublicKey:  publicKey,
				HeaderName: "X-Token",
			},
			wantErr: false,
		},
		{
			name: "valid config - full",
			config: &JWTConfig{
				PublicKey:  publicKey,
				Issuer:     "https://auth.example.com",
				Audience:   []string{"api.example.com", "app.example.com"},
				HeaderName: "Authorization",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := NewJWTAuthenticator(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if err.Error() != tt.errMsg {
					t.Errorf("error = %v, want %v", err.Error(), tt.errMsg)
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

func TestJWTAuthenticator_AuthenticateHTTP(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)

	tests := []struct {
		name        string
		config      *JWTConfig
		setupReq    func(*http.Request, *ecdsa.PrivateKey)
		wantErr     bool
		wantSubject string
	}{
		{
			name: "valid bearer token",
			config: &JWTConfig{
				PublicKey: publicKey,
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub": "user123",
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr:     false,
			wantSubject: "user123",
		},
		{
			name: "valid token without Bearer prefix",
			config: &JWTConfig{
				PublicKey: publicKey,
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub": "user456",
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				req.Header.Set("Authorization", token)
			},
			wantErr:     false,
			wantSubject: "user456",
		},
		{
			name: "custom header name",
			config: &JWTConfig{
				PublicKey:  publicKey,
				HeaderName: "X-Auth-Token",
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub": "user789",
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				req.Header.Set("X-Auth-Token", "Bearer "+token)
			},
			wantErr:     false,
			wantSubject: "user789",
		},
		{
			name: "no authorization header",
			config: &JWTConfig{
				PublicKey: publicKey,
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				// No header set
			},
			wantErr: true,
		},
		{
			name: "empty Bearer token",
			config: &JWTConfig{
				PublicKey: publicKey,
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				req.Header.Set("Authorization", "Bearer ")
			},
			wantErr: true,
		},
		{
			name: "invalid token",
			config: &JWTConfig{
				PublicKey: publicKey,
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				req.Header.Set("Authorization", "Bearer invalidtoken")
			},
			wantErr: true,
		},
		{
			name: "expired token",
			config: &JWTConfig{
				PublicKey: publicKey,
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub": "user123",
					"exp": time.Now().Add(-time.Hour).Unix(), // Expired
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr: true,
		},
		{
			name: "missing subject claim",
			config: &JWTConfig{
				PublicKey: publicKey,
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"exp": time.Now().Add(time.Hour).Unix(),
					// No "sub" claim
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr: true,
		},
		{
			name: "valid issuer",
			config: &JWTConfig{
				PublicKey: publicKey,
				Issuer:    "https://auth.example.com",
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub": "user123",
					"iss": "https://auth.example.com",
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr:     false,
			wantSubject: "user123",
		},
		{
			name: "invalid issuer",
			config: &JWTConfig{
				PublicKey: publicKey,
				Issuer:    "https://auth.example.com",
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub": "user123",
					"iss": "https://evil.example.com",
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr: true,
		},
		{
			name: "missing issuer when required",
			config: &JWTConfig{
				PublicKey: publicKey,
				Issuer:    "https://auth.example.com",
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub": "user123",
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr: true,
		},
		{
			name: "valid audience - single string",
			config: &JWTConfig{
				PublicKey: publicKey,
				Audience:  []string{"api.example.com"},
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub": "user123",
					"aud": "api.example.com",
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr:     false,
			wantSubject: "user123",
		},
		{
			name: "valid audience - array",
			config: &JWTConfig{
				PublicKey: publicKey,
				Audience:  []string{"api.example.com"},
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub": "user123",
					"aud": []interface{}{"api.example.com", "other.example.com"},
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr:     false,
			wantSubject: "user123",
		},
		{
			name: "invalid audience - string",
			config: &JWTConfig{
				PublicKey: publicKey,
				Audience:  []string{"api.example.com"},
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub": "user123",
					"aud": "wrong.example.com",
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr: true,
		},
		{
			name: "invalid audience - array",
			config: &JWTConfig{
				PublicKey: publicKey,
				Audience:  []string{"api.example.com"},
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub": "user123",
					"aud": []interface{}{"wrong.example.com", "other.example.com"},
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr: true,
		},
		{
			name: "invalid audience format",
			config: &JWTConfig{
				PublicKey: publicKey,
				Audience:  []string{"api.example.com"},
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub": "user123",
					"aud": 12345, // Invalid type
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr: true,
		},
		{
			name: "token with role claim",
			config: &JWTConfig{
				PublicKey: publicKey,
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub":  "user123",
					"role": "admin",
					"exp":  time.Now().Add(time.Hour).Unix(),
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr:     false,
			wantSubject: "user123",
		},
		{
			name: "token with username claim",
			config: &JWTConfig{
				PublicKey: publicKey,
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub":      "user123",
					"username": "johndoe",
					"exp":      time.Now().Add(time.Hour).Unix(),
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr:     false,
			wantSubject: "user123",
		},
		{
			name: "token with name claim",
			config: &JWTConfig{
				PublicKey: publicKey,
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub":  "user123",
					"name": "John Doe",
					"exp":  time.Now().Add(time.Hour).Unix(),
				})
				req.Header.Set("Authorization", "Bearer "+token)
			},
			wantErr:     false,
			wantSubject: "user123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := NewJWTAuthenticator(tt.config)
			if err != nil {
				t.Fatalf("failed to create authenticator: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			tt.setupReq(req, privateKey)

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
			if identity.Attributes["auth_method"] != "jwt" {
				t.Errorf("auth_method = %v, want jwt", identity.Attributes["auth_method"])
			}
			if identity.Attributes["remote_addr"] == "" {
				t.Error("expected remote_addr to be set")
			}
		})
	}
}

func TestJWTAuthenticator_AuthenticateGRPC(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)

	tests := []struct {
		name        string
		config      *JWTConfig
		setupMD     func(metadata.MD, *ecdsa.PrivateKey)
		wantErr     bool
		wantSubject string
	}{
		{
			name: "valid bearer token in authorization",
			config: &JWTConfig{
				PublicKey: publicKey,
			},
			setupMD: func(md metadata.MD, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub": "grpc-user",
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				md.Set("authorization", "Bearer "+token)
			},
			wantErr:     false,
			wantSubject: "grpc-user",
		},
		{
			name: "valid token without Bearer prefix in metadata",
			config: &JWTConfig{
				PublicKey: publicKey,
			},
			setupMD: func(md metadata.MD, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub": "grpc-user2",
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				md.Set("authorization", token)
			},
			wantErr:     false,
			wantSubject: "grpc-user2",
		},
		{
			name: "custom header name in metadata",
			config: &JWTConfig{
				PublicKey:  publicKey,
				HeaderName: "X-Auth-Token",
			},
			setupMD: func(md metadata.MD, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub": "grpc-user3",
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				md.Set("x-auth-token", "Bearer "+token)
			},
			wantErr:     false,
			wantSubject: "grpc-user3",
		},
		{
			name: "no token in metadata",
			config: &JWTConfig{
				PublicKey: publicKey,
			},
			setupMD: func(md metadata.MD, key *ecdsa.PrivateKey) {
				// No token set
			},
			wantErr: true,
		},
		{
			name: "invalid token in metadata",
			config: &JWTConfig{
				PublicKey: publicKey,
			},
			setupMD: func(md metadata.MD, key *ecdsa.PrivateKey) {
				md.Set("authorization", "Bearer invalidtoken")
			},
			wantErr: true,
		},
		{
			name: "expired token in metadata",
			config: &JWTConfig{
				PublicKey: publicKey,
			},
			setupMD: func(md metadata.MD, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub": "grpc-user",
					"exp": time.Now().Add(-time.Hour).Unix(), // Expired
				})
				md.Set("authorization", "Bearer "+token)
			},
			wantErr: true,
		},
		{
			name: "valid issuer in metadata",
			config: &JWTConfig{
				PublicKey: publicKey,
				Issuer:    "https://auth.example.com",
			},
			setupMD: func(md metadata.MD, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub": "grpc-user",
					"iss": "https://auth.example.com",
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				md.Set("authorization", "Bearer "+token)
			},
			wantErr:     false,
			wantSubject: "grpc-user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := NewJWTAuthenticator(tt.config)
			if err != nil {
				t.Fatalf("failed to create authenticator: %v", err)
			}

			ctx := context.Background()
			md := metadata.MD{}
			tt.setupMD(md, privateKey)

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
			if identity.Attributes["auth_method"] != "jwt" {
				t.Errorf("auth_method = %v, want jwt", identity.Attributes["auth_method"])
			}
		})
	}
}

func TestJWTAuthenticator_Name(t *testing.T) {
	_, publicKey := generateTestKeyPair(t)

	auth, err := NewJWTAuthenticator(&JWTConfig{
		PublicKey: publicKey,
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	name := auth.Name()
	if name != "jwt" {
		t.Errorf("Name() = %v, want jwt", name)
	}
}

func TestJWTAuthenticator_IdentityAttributes(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)

	auth, err := NewJWTAuthenticator(&JWTConfig{
		PublicKey: publicKey,
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	token := createTestToken(t, privateKey, jwt.MapClaims{
		"sub":      "user123",
		"role":     "admin",
		"username": "johndoe",
		"name":     "John Doe",
		"custom":   "value",
		"exp":      time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	identity, err := auth.AuthenticateHTTP(req)
	if err != nil {
		t.Fatalf("AuthenticateHTTP() error = %v", err)
	}

	// Check subject
	if identity.Subject != "user123" {
		t.Errorf("Subject = %v, want user123", identity.Subject)
	}

	// Check role is converted to roles array
	if roles, ok := identity.Claims["roles"].([]string); !ok || len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("roles = %v, want [admin]", identity.Claims["roles"])
	}

	// Check username attribute
	if identity.Attributes["username"] != "johndoe" {
		t.Errorf("username = %v, want johndoe", identity.Attributes["username"])
	}

	// Check display name attribute
	if identity.Attributes["display_name"] != "John Doe" {
		t.Errorf("display_name = %v, want John Doe", identity.Attributes["display_name"])
	}

	// Check custom claim is preserved
	if identity.Claims["custom"] != "value" {
		t.Errorf("custom claim = %v, want value", identity.Claims["custom"])
	}
}

func TestJWTAuthenticator_WrongSigningKey(t *testing.T) {
	privateKey, _ := generateTestKeyPair(t)
	_, differentPublicKey := generateTestKeyPair(t)

	auth, err := NewJWTAuthenticator(&JWTConfig{
		PublicKey: differentPublicKey, // Different key than used for signing
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	token := createTestToken(t, privateKey, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err = auth.AuthenticateHTTP(req)
	if err == nil {
		t.Error("expected error for token signed with different key")
	}
}

func TestJWTAuthenticator_MultipleAudienceMatch(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)

	auth, err := NewJWTAuthenticator(&JWTConfig{
		PublicKey: publicKey,
		Audience:  []string{"api.example.com", "web.example.com", "app.example.com"},
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Test with second audience
	token := createTestToken(t, privateKey, jwt.MapClaims{
		"sub": "user123",
		"aud": "web.example.com",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	identity, err := auth.AuthenticateHTTP(req)
	if err != nil {
		t.Fatalf("AuthenticateHTTP() error = %v", err)
	}
	if identity.Subject != "user123" {
		t.Errorf("Subject = %v, want user123", identity.Subject)
	}

	// Test with array audience that has a match
	token2 := createTestToken(t, privateKey, jwt.MapClaims{
		"sub": "user456",
		"aud": []interface{}{"other.example.com", "app.example.com"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", "Bearer "+token2)

	identity2, err := auth.AuthenticateHTTP(req2)
	if err != nil {
		t.Fatalf("AuthenticateHTTP() error = %v", err)
	}
	if identity2.Subject != "user456" {
		t.Errorf("Subject = %v, want user456", identity2.Subject)
	}
}
