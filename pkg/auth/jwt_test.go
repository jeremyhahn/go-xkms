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
	"crypto/rsa"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		{
			// A raw byte secret is what a caller would (mis)configure to get
			// HMAC verification. JWTAuthenticator is an asymmetric-key-only
			// verifier: refusing this at construction time is what makes an
			// HS*-signed token impossible to ever validate through it.
			name: "unsupported key type (HMAC secret)",
			config: &JWTConfig{
				PublicKey: []byte("some-hmac-secret-bytes"),
			},
			wantErr: true,
			errMsg:  (&UnsupportedVerificationKeyError{KeyType: "[]uint8"}).Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := NewJWTAuthenticator(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.errMsg, err.Error())
				return
			}
			require.NoError(t, err)
			require.NotNil(t, auth)
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
			// jwt.WithExpirationRequired refuses a token with no exp claim
			// at all: without it, jwt/v5's default expiry check is a no-op,
			// which is the same as bearer authentication accepting a
			// permanent credential.
			name: "missing exp claim",
			config: &JWTConfig{
				PublicKey: publicKey,
			},
			setupReq: func(req *http.Request, key *ecdsa.PrivateKey) {
				token := createTestToken(t, key, jwt.MapClaims{
					"sub": "user123",
					// No "exp" claim
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
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			tt.setupReq(req, privateKey)

			identity, err := auth.AuthenticateHTTP(req)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, identity)
			assert.Equal(t, tt.wantSubject, identity.Subject)
			assert.Equal(t, "jwt", identity.Metadata["auth_method"])
			assert.NotEmpty(t, identity.Metadata["remote_addr"])
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
			require.NoError(t, err)

			ctx := context.Background()
			md := metadata.MD{}
			tt.setupMD(md, privateKey)

			identity, err := auth.AuthenticateGRPC(ctx, md)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, identity)
			assert.Equal(t, tt.wantSubject, identity.Subject)
			assert.Equal(t, "jwt", identity.Metadata["auth_method"])
		})
	}
}

func TestJWTAuthenticator_Name(t *testing.T) {
	_, publicKey := generateTestKeyPair(t)

	auth, err := NewJWTAuthenticator(&JWTConfig{
		PublicKey: publicKey,
	})
	require.NoError(t, err)

	assert.Equal(t, "jwt", auth.Name())
}

func TestJWTAuthenticator_IdentityFields(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)

	auth, err := NewJWTAuthenticator(&JWTConfig{
		PublicKey: publicKey,
	})
	require.NoError(t, err)

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
	require.NoError(t, err)

	// Check subject
	assert.Equal(t, "user123", identity.Subject)

	// Check role is mapped onto Identity.Roles
	assert.Equal(t, []string{"admin"}, identity.Roles)

	// Check username metadata
	assert.Equal(t, "johndoe", identity.Metadata["username"])

	// Check display name metadata
	assert.Equal(t, "John Doe", identity.Metadata["display_name"])
}

func TestJWTAuthenticator_WrongSigningKey(t *testing.T) {
	privateKey, _ := generateTestKeyPair(t)
	_, differentPublicKey := generateTestKeyPair(t)

	auth, err := NewJWTAuthenticator(&JWTConfig{
		PublicKey: differentPublicKey, // Different key than used for signing
	})
	require.NoError(t, err)

	token := createTestToken(t, privateKey, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err = auth.AuthenticateHTTP(req)
	require.Error(t, err)
}

// TestJWTAuthenticator_RejectsHS256AlgorithmConfusion is the failure test
// for the crypto audit's JWT algorithm-pinning finding. Without
// jwt.WithValidMethods pinned to the verification key's type, a token
// forged with alg: HS256 and "signed" using the server's own public key
// bytes as the HMAC secret would let the key function's returned value
// double as a symmetric secret. validateToken must refuse the token before
// that check ever runs, because JWTAuthenticator's key here is ECDSA and
// only ES* is valid for it.
func TestJWTAuthenticator_RejectsHS256AlgorithmConfusion(t *testing.T) {
	_, publicKey := generateTestKeyPair(t)

	auth, err := NewJWTAuthenticator(&JWTConfig{PublicKey: publicKey})
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(pubKeyBytes)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	_, err = auth.AuthenticateHTTP(req)
	require.Error(t, err)
}

// TestJWTAuthenticator_AcceptsRS256WithRSAKey is the success counterpart:
// an RSA-keyed authenticator still accepts a validly RS256-signed token
// once algorithm pinning is in place (RS256 is in the RSA method set).
func TestJWTAuthenticator_AcceptsRS256WithRSAKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	auth, err := NewJWTAuthenticator(&JWTConfig{PublicKey: &privateKey.PublicKey})
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	identity, err := auth.AuthenticateHTTP(req)
	require.NoError(t, err)
	assert.Equal(t, "user123", identity.Subject)
}

func TestJWTAuthenticator_MultipleAudienceMatch(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)

	auth, err := NewJWTAuthenticator(&JWTConfig{
		PublicKey: publicKey,
		Audience:  []string{"api.example.com", "web.example.com", "app.example.com"},
	})
	require.NoError(t, err)

	// Test with second audience
	token := createTestToken(t, privateKey, jwt.MapClaims{
		"sub": "user123",
		"aud": "web.example.com",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	identity, err := auth.AuthenticateHTTP(req)
	require.NoError(t, err)
	assert.Equal(t, "user123", identity.Subject)

	// Test with array audience that has a match
	token2 := createTestToken(t, privateKey, jwt.MapClaims{
		"sub": "user456",
		"aud": []interface{}{"other.example.com", "app.example.com"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", "Bearer "+token2)

	identity2, err := auth.AuthenticateHTTP(req2)
	require.NoError(t, err)
	assert.Equal(t, "user456", identity2.Subject)
}

func TestJWTAuthenticator_TenantID(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)

	auth, err := NewJWTAuthenticator(&JWTConfig{
		PublicKey: publicKey,
	})
	require.NoError(t, err)

	token := createTestToken(t, privateKey, jwt.MapClaims{
		"sub":       "user123",
		"tenant_id": "tenant-xyz",
		"exp":       time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	identity, err := auth.AuthenticateHTTP(req)
	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, "user123", identity.Subject)
	assert.Equal(t, "tenant-xyz", identity.TenantID)
	assert.False(t, IsCrossTenant(identity))
}

func TestJWTAuthenticator_NoTenantID(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)

	auth, err := NewJWTAuthenticator(&JWTConfig{
		PublicKey: publicKey,
	})
	require.NoError(t, err)

	token := createTestToken(t, privateKey, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	identity, err := auth.AuthenticateHTTP(req)
	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, "user123", identity.Subject)
	assert.Empty(t, identity.TenantID)
	assert.True(t, IsCrossTenant(identity))
}

// TestJWTAuthenticator_EmailClaim proves the canonical login key claim is
// surfaced on the identity (go-xkms#194).
func TestJWTAuthenticator_EmailClaim(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)

	auth, err := NewJWTAuthenticator(&JWTConfig{PublicKey: publicKey})
	require.NoError(t, err)

	token := createTestToken(t, privateKey, jwt.MapClaims{
		"sub":      "user123",
		"username": "johndoe",
		"email":    "john@example.com",
		"exp":      time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	identity, err := auth.AuthenticateHTTP(req)
	require.NoError(t, err)
	assert.Equal(t, "john@example.com", identity.Metadata["email"])
	assert.Equal(t, "johndoe", identity.Metadata["username"])
}

// TestJWTAuthenticator_EmailClaimAbsentOrEmpty proves a token without an
// email claim, or with an empty one, leaves the metadata key absent rather
// than recording an empty login key.
func TestJWTAuthenticator_EmailClaimAbsentOrEmpty(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)

	auth, err := NewJWTAuthenticator(&JWTConfig{PublicKey: publicKey})
	require.NoError(t, err)

	cases := map[string]jwt.MapClaims{
		"absent": {
			"sub": "svc",
			"exp": time.Now().Add(time.Hour).Unix(),
		},
		"empty": {
			"sub":   "svc",
			"email": "",
			"exp":   time.Now().Add(time.Hour).Unix(),
		},
		"non-string": {
			"sub":   "svc",
			"email": 42,
			"exp":   time.Now().Add(time.Hour).Unix(),
		},
	}

	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			token := createTestToken(t, privateKey, claims)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+token)

			identity, err := auth.AuthenticateHTTP(req)
			require.NoError(t, err)
			_, present := identity.Metadata["email"]
			assert.False(t, present, "email must be absent, got %q", identity.Metadata["email"])
		})
	}
}

// TestJWTAuthenticator_AttestLevelClaim proves the attestation level the PIV
// login minted reaches the identity a handler sees behind bearer auth, and
// that a token without the claim leaves the key absent.
func TestJWTAuthenticator_AttestLevelClaim(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	auth, err := NewJWTAuthenticator(&JWTConfig{PublicKey: publicKey})
	require.NoError(t, err)

	for _, level := range []string{"hardware", "unattested"} {
		token := createTestToken(t, privateKey, jwt.MapClaims{
			"sub":          "user123",
			"attest_level": level,
			"exp":          time.Now().Add(time.Hour).Unix(),
		})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		identity, err := auth.AuthenticateHTTP(req)
		require.NoError(t, err)
		assert.Equal(t, level, identity.Metadata["attest_level"])
	}

	for name, claims := range map[string]jwt.MapClaims{
		"absent": {"sub": "user123", "exp": time.Now().Add(time.Hour).Unix()},
		"empty":  {"sub": "user123", "attest_level": "", "exp": time.Now().Add(time.Hour).Unix()},
		"wrong":  {"sub": "user123", "attest_level": 1, "exp": time.Now().Add(time.Hour).Unix()},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+createTestToken(t, privateKey, claims))
		identity, err := auth.AuthenticateHTTP(req)
		require.NoError(t, err, name)
		_, present := identity.Metadata["attest_level"]
		assert.False(t, present, "%s: attest_level must be absent, got %q", name, identity.Metadata["attest_level"])
	}
}

// TestJWTAuthenticator_RejectsRefreshTokens proves a token carrying the
// refresh marker is refused as a bearer credential even though it is validly
// signed and carries a subject: its lifetime is the refresh endpoint's, not a
// protected route's.
func TestJWTAuthenticator_RejectsRefreshTokens(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	auth, err := NewJWTAuthenticator(&JWTConfig{PublicKey: publicKey})
	require.NoError(t, err)

	refresh := createTestToken(t, privateKey, jwt.MapClaims{
		"sub":          "user123",
		"typ":          RefreshTokenType,
		"attest_level": "hardware",
		"exp":          time.Now().Add(8 * time.Hour).Unix(),
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+refresh)
	_, err = auth.AuthenticateHTTP(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh token")

	access := createTestToken(t, privateKey, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	_, err = auth.AuthenticateHTTP(req)
	require.NoError(t, err, "a token without the marker is an access token")
}
