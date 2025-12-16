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

package webauthn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockWebAuthnUser implements the User interface for testing
type mockWebAuthnUser struct {
	id          []byte
	name        string
	displayName string
	email       string
	credentials []webauthn.Credential
	sessionData []byte
	role        string
}

func (u *mockWebAuthnUser) WebAuthnID() []byte {
	return u.id
}

func (u *mockWebAuthnUser) WebAuthnName() string {
	return u.name
}

func (u *mockWebAuthnUser) WebAuthnDisplayName() string {
	return u.displayName
}

func (u *mockWebAuthnUser) WebAuthnIcon() string {
	return ""
}

func (u *mockWebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func (u *mockWebAuthnUser) GetRole() string {
	return u.role
}

func (u *mockWebAuthnUser) AddCredential(cred *Credential) {
	u.credentials = append(u.credentials, webauthn.Credential{
		ID:              cred.ID,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
	})
}

func (u *mockWebAuthnUser) UpdateCredential(cred *Credential) {
	for i, c := range u.credentials {
		if string(c.ID) == string(cred.ID) {
			u.credentials[i].PublicKey = cred.PublicKey
			u.credentials[i].AttestationType = cred.AttestationType
			return
		}
	}
}

func (u *mockWebAuthnUser) SetSessionData(data []byte) {
	u.sessionData = data
}

func (u *mockWebAuthnUser) SessionData() []byte {
	return u.sessionData
}

func (u *mockWebAuthnUser) Email() string {
	return u.email
}

func (u *mockWebAuthnUser) DisplayName() string {
	return u.displayName
}

func TestNewDefaultJWTGenerator(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name    string
		config  *JWTGeneratorConfig
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
			name:    "nil private key",
			config:  &JWTGeneratorConfig{},
			wantErr: true,
			errMsg:  "private key is required",
		},
		{
			name: "valid minimal config",
			config: &JWTGeneratorConfig{
				PrivateKey: privateKey,
			},
			wantErr: false,
		},
		{
			name: "valid full config",
			config: &JWTGeneratorConfig{
				PrivateKey: privateKey,
				PublicKey:  &privateKey.PublicKey,
				Issuer:     "test-issuer",
				Audience:   []string{"test-audience"},
				ExpiresIn:  30 * time.Minute,
				KeyID:      "test-key-id",
			},
			wantErr: false,
		},
		{
			name: "config without public key - derives from private",
			config: &JWTGeneratorConfig{
				PrivateKey: privateKey,
				Issuer:     "custom-issuer",
				Audience:   []string{"custom-audience"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen, err := NewDefaultJWTGenerator(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, gen)
		})
	}
}

func TestDefaultJWTGenerator_GenerateToken(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name      string
		config    *JWTGeneratorConfig
		user      User
		wantErr   bool
		checkRole bool
	}{
		{
			name: "basic token generation",
			config: &JWTGeneratorConfig{
				PrivateKey: privateKey,
			},
			user: &mockWebAuthnUser{
				id:          []byte("user-123"),
				name:        "testuser",
				displayName: "Test User",
			},
			wantErr: false,
		},
		{
			name: "token with custom issuer and audience",
			config: &JWTGeneratorConfig{
				PrivateKey: privateKey,
				Issuer:     "custom-issuer",
				Audience:   []string{"custom-audience"},
				ExpiresIn:  2 * time.Hour,
			},
			user: &mockWebAuthnUser{
				id:          []byte("user-456"),
				name:        "customuser",
				displayName: "Custom User",
			},
			wantErr: false,
		},
		{
			name: "token with key ID",
			config: &JWTGeneratorConfig{
				PrivateKey: privateKey,
				KeyID:      "my-key-id",
			},
			user: &mockWebAuthnUser{
				id:          []byte("user-789"),
				name:        "keyiduser",
				displayName: "KeyID User",
			},
			wantErr: false,
		},
		{
			name: "token with role",
			config: &JWTGeneratorConfig{
				PrivateKey: privateKey,
			},
			user: &mockWebAuthnUser{
				id:          []byte("admin-user"),
				name:        "adminuser",
				displayName: "Admin User",
				role:        "admin",
			},
			wantErr:   false,
			checkRole: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen, err := NewDefaultJWTGenerator(tt.config)
			require.NoError(t, err)

			ctx := context.Background()
			token, err := gen.GenerateToken(ctx, tt.user)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotEmpty(t, token)

			// Verify the token
			claims, err := gen.VerifyToken(token)
			require.NoError(t, err)
			assert.NotNil(t, claims)

			// Check claims
			assert.Equal(t, tt.user.WebAuthnName(), claims["username"])
			assert.Equal(t, tt.user.WebAuthnDisplayName(), claims["name"])

			// Check role if applicable
			if tt.checkRole {
				if roleUser, ok := tt.user.(*mockWebAuthnUser); ok {
					assert.Equal(t, roleUser.role, claims["role"])
				}
			}
		})
	}
}

func TestDefaultJWTGenerator_VerifyToken(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	gen, err := NewDefaultJWTGenerator(&JWTGeneratorConfig{
		PrivateKey: privateKey,
		Issuer:     "test-issuer",
		Audience:   []string{"test-audience"},
		ExpiresIn:  time.Hour,
	})
	require.NoError(t, err)

	user := &mockWebAuthnUser{
		id:          []byte("verify-user"),
		name:        "verifyuser",
		displayName: "Verify User",
	}

	ctx := context.Background()
	token, err := gen.GenerateToken(ctx, user)
	require.NoError(t, err)

	// Verify valid token
	claims, err := gen.VerifyToken(token)
	require.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, "test-issuer", claims["iss"])
	assert.Equal(t, "verifyuser", claims["username"])
	assert.Equal(t, "Verify User", claims["name"])
}

func TestDefaultJWTGenerator_VerifyToken_InvalidToken(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	gen, err := NewDefaultJWTGenerator(&JWTGeneratorConfig{
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	// Test with invalid token
	_, err = gen.VerifyToken("invalid-token")
	require.Error(t, err)
}

func TestDefaultJWTGenerator_VerifyToken_WrongKey(t *testing.T) {
	privateKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privateKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	gen1, err := NewDefaultJWTGenerator(&JWTGeneratorConfig{
		PrivateKey: privateKey1,
	})
	require.NoError(t, err)

	gen2, err := NewDefaultJWTGenerator(&JWTGeneratorConfig{
		PrivateKey: privateKey2,
	})
	require.NoError(t, err)

	user := &mockWebAuthnUser{
		id:          []byte("wrong-key-user"),
		name:        "wrongkeyuser",
		displayName: "Wrong Key User",
	}

	ctx := context.Background()
	token, err := gen1.GenerateToken(ctx, user)
	require.NoError(t, err)

	// Try to verify with different generator (different key)
	_, err = gen2.VerifyToken(token)
	require.Error(t, err)
}

func TestDefaultJWTGenerator_PublicKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	gen, err := NewDefaultJWTGenerator(&JWTGeneratorConfig{
		PrivateKey: privateKey,
	})
	require.NoError(t, err)

	pubKey := gen.PublicKey()
	assert.NotNil(t, pubKey)
	assert.Equal(t, &privateKey.PublicKey, pubKey)
}

func TestDefaultJWTGenerator_Issuer(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name           string
		configIssuer   string
		expectedIssuer string
	}{
		{
			name:           "default issuer",
			configIssuer:   "",
			expectedIssuer: "go-keychain",
		},
		{
			name:           "custom issuer",
			configIssuer:   "my-custom-issuer",
			expectedIssuer: "my-custom-issuer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen, err := NewDefaultJWTGenerator(&JWTGeneratorConfig{
				PrivateKey: privateKey,
				Issuer:     tt.configIssuer,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.expectedIssuer, gen.Issuer())
		})
	}
}

func TestDefaultJWTGenerator_Audience(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name             string
		configAudience   []string
		expectedAudience []string
	}{
		{
			name:             "default audience",
			configAudience:   nil,
			expectedAudience: []string{"go-keychain"},
		},
		{
			name:             "empty audience slice",
			configAudience:   []string{},
			expectedAudience: []string{"go-keychain"},
		},
		{
			name:             "single custom audience",
			configAudience:   []string{"my-audience"},
			expectedAudience: []string{"my-audience"},
		},
		{
			name:             "multiple audiences",
			configAudience:   []string{"audience1", "audience2"},
			expectedAudience: []string{"audience1", "audience2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen, err := NewDefaultJWTGenerator(&JWTGeneratorConfig{
				PrivateKey: privateKey,
				Audience:   tt.configAudience,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.expectedAudience, gen.Audience())
		})
	}
}

func TestDefaultJWTGenerator_ExpiresIn(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name            string
		configExpiresIn time.Duration
		expectedExpiry  time.Duration
	}{
		{
			name:            "default expiry",
			configExpiresIn: 0,
			expectedExpiry:  time.Hour,
		},
		{
			name:            "custom 30 minutes",
			configExpiresIn: 30 * time.Minute,
			expectedExpiry:  30 * time.Minute,
		},
		{
			name:            "custom 2 hours",
			configExpiresIn: 2 * time.Hour,
			expectedExpiry:  2 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen, err := NewDefaultJWTGenerator(&JWTGeneratorConfig{
				PrivateKey: privateKey,
				ExpiresIn:  tt.configExpiresIn,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.expectedExpiry, gen.ExpiresIn())
		})
	}
}

func TestDefaultJWTGenerator_RoundTrip(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	gen, err := NewDefaultJWTGenerator(&JWTGeneratorConfig{
		PrivateKey: privateKey,
		Issuer:     "round-trip-issuer",
		Audience:   []string{"round-trip-audience"},
		ExpiresIn:  time.Hour,
		KeyID:      "round-trip-key",
	})
	require.NoError(t, err)

	user := &mockWebAuthnUser{
		id:          []byte("round-trip-user-id"),
		name:        "roundtripuser",
		displayName: "Round Trip User",
		role:        "user",
	}

	ctx := context.Background()

	// Generate multiple tokens and verify each
	for i := 0; i < 10; i++ {
		token, err := gen.GenerateToken(ctx, user)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		claims, err := gen.VerifyToken(token)
		require.NoError(t, err)

		assert.Equal(t, "round-trip-issuer", claims["iss"])
		assert.Equal(t, "roundtripuser", claims["username"])
		assert.Equal(t, "Round Trip User", claims["name"])
		assert.Equal(t, "user", claims["role"])
	}
}

func TestDefaultJWTGenerator_WithoutPublicKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	gen, err := NewDefaultJWTGenerator(&JWTGeneratorConfig{
		PrivateKey: privateKey,
		// No explicit PublicKey - should derive from PrivateKey
	})
	require.NoError(t, err)

	// Public key should have been derived
	assert.NotNil(t, gen.PublicKey())

	user := &mockWebAuthnUser{
		id:          []byte("no-pub-user"),
		name:        "nopubuser",
		displayName: "No Pub User",
	}

	ctx := context.Background()
	token, err := gen.GenerateToken(ctx, user)
	require.NoError(t, err)

	// Should be able to verify
	claims, err := gen.VerifyToken(token)
	require.NoError(t, err)
	assert.Equal(t, "nopubuser", claims["username"])
}

func TestDefaultJWTGenerator_DifferentCurves(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			gen, err := NewDefaultJWTGenerator(&JWTGeneratorConfig{
				PrivateKey: privateKey,
			})
			require.NoError(t, err)

			user := &mockWebAuthnUser{
				id:          []byte("curve-user-" + tc.name),
				name:        "curveuser",
				displayName: "Curve User " + tc.name,
			}

			ctx := context.Background()
			token, err := gen.GenerateToken(ctx, user)
			require.NoError(t, err)

			claims, err := gen.VerifyToken(token)
			require.NoError(t, err)
			assert.Equal(t, "curveuser", claims["username"])
		})
	}
}
